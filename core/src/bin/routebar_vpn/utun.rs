//! Owned, nonblocking macOS utun descriptor. Network configuration lives elsewhere.
//!
//! ABI: the macOS SDK's sys/kern_control.h, sys/sys_domain.h and net/if_utun.h.
//! The four-byte address-family prefix is in network byte order, as documented in
//! Apple's xnu/bsd/net/if_utun.c (utun_ctl_send and utun_output).

use std::{
    io,
    mem::{size_of, zeroed},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

const CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
const UTUN_OPT_IFNAME: libc::c_int = 2;
const MAX_IP_PACKET: usize = 65535;

pub struct Utun {
    fd: OwnedFd,
    name: String,
}

impl Utun {
    /// Create an unconfigured utun interface. Closing this owned descriptor
    /// detaches the interface; callers must separately undo their DNS settings.
    pub fn create() -> io::Result<Self> {
        // SAFETY: socket takes scalar constants and returns an owned descriptor.
        let raw =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly created descriptor and has no other owner.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        set_flag(raw, libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC)?;

        // SAFETY: ctl_info is a C integer/byte-array structure with valid zeros.
        let mut control: libc::ctl_info = unsafe { zeroed() };
        for (to, from) in control.ctl_name.iter_mut().zip(CONTROL_NAME) {
            *to = *from as libc::c_char;
        }
        // SAFETY: ioctl receives a live, writable ctl_info of the SDK ABI size.
        if unsafe { libc::ioctl(raw, libc::CTLIOCGINFO, &mut control) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let address = libc::sockaddr_ctl {
            sc_len: size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: control.ctl_id,
            sc_unit: 0, // Let the kernel allocate an available utun unit.
            sc_reserved: [0; 5],
        };
        // SAFETY: address is a valid sockaddr_ctl and remains live for the call.
        if unsafe {
            libc::connect(
                raw,
                (&address as *const libc::sockaddr_ctl).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut bytes = [0u8; libc::IFNAMSIZ];
        let mut length = bytes.len() as libc::socklen_t;
        // SAFETY: bytes and length are writable, correctly sized output buffers.
        if unsafe {
            libc::getsockopt(
                raw,
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                bytes.as_mut_ptr().cast(),
                &mut length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let name = interface_name(&bytes, length as usize)?;
        set_flag(raw, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)?;
        Ok(Self { fd, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Consume one datagram and return its IP bytes without the utun header.
    /// InvalidData means a malformed/oversized datagram was consumed and dropped.
    pub fn read_packet(&self, packet: &mut [u8]) -> io::Result<usize> {
        if packet.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Empty packet buffer",
            ));
        }
        let mut family = [0u8; 4];
        let mut buffers = [
            libc::iovec {
                iov_base: family.as_mut_ptr().cast(),
                iov_len: family.len(),
            },
            libc::iovec {
                iov_base: packet.as_mut_ptr().cast(),
                iov_len: packet.len().min(MAX_IP_PACKET),
            },
        ];
        // SAFETY: msghdr permits null optional buffers; the two iovecs point to
        // non-overlapping writable slices which outlive the synchronous syscall.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = buffers.as_mut_ptr();
        message.msg_iovlen = buffers.len() as _;
        // SAFETY: descriptor and all buffers above are live for this call.
        let count = unsafe { libc::recvmsg(self.as_raw_fd(), &mut message, 0) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count < 4 || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Err(invalid_packet());
        }
        let count = count as usize - 4;
        if count > packet.len().min(MAX_IP_PACKET) {
            return Err(invalid_packet());
        }
        validate_family(family, &packet[..count])?;
        Ok(count)
    }

    /// Inject one complete IP datagram. No partial writes or packet splitting.
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let family = packet_family(packet)?.to_be_bytes();
        let buffers = [
            libc::iovec {
                iov_base: family.as_ptr().cast_mut().cast(),
                iov_len: family.len(),
            },
            libc::iovec {
                iov_base: packet.as_ptr().cast_mut().cast(),
                iov_len: packet.len(),
            },
        ];
        // SAFETY: writev reads but never mutates the borrowed family/packet data.
        let count = unsafe { libc::writev(self.as_raw_fd(), buffers.as_ptr(), buffers.len() as _) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize != family.len() + packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Incomplete utun datagram write",
            ));
        }
        Ok(())
    }
}

impl AsRawFd for Utun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn set_flag(fd: RawFd, get: libc::c_int, set: libc::c_int, flag: libc::c_int) -> io::Result<()> {
    // SAFETY: the caller owns fd; these fcntl operations use integer arguments.
    let previous = unsafe { libc::fcntl(fd, get) };
    if previous < 0 || unsafe { libc::fcntl(fd, set, previous | flag) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn interface_name(bytes: &[u8], length: usize) -> io::Result<String> {
    let supplied = bytes.get(..length).ok_or_else(invalid_packet)?;
    let end = supplied
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(invalid_packet)?;
    let name = std::str::from_utf8(&supplied[..end]).map_err(|_| invalid_packet())?;
    if !name.strip_prefix("utun").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid utun interface name",
        ));
    }
    Ok(name.to_owned())
}

fn invalid_packet() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Malformed or truncated utun packet",
    )
}

fn packet_family(packet: &[u8]) -> io::Result<u32> {
    if packet.len() > MAX_IP_PACKET {
        return Err(invalid_packet());
    }
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = ((packet[0] & 0x0f) as usize) * 4;
            let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if header < 20 || header > packet.len() || length != packet.len() {
                return Err(invalid_packet());
            }
            Ok(libc::AF_INET as u32)
        }
        Some(6) if packet.len() >= 40 => {
            let length = u16::from_be_bytes([packet[4], packet[5]]) as usize + 40;
            if length != packet.len() {
                return Err(invalid_packet());
            }
            Ok(libc::AF_INET6 as u32)
        }
        _ => Err(invalid_packet()),
    }
}

fn validate_family(family: [u8; 4], packet: &[u8]) -> io::Result<()> {
    if u32::from_be_bytes(family) != packet_family(packet)? {
        return Err(invalid_packet());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    fn packet4() -> Vec<u8> {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet
    }

    fn packet6() -> Vec<u8> {
        let mut packet = vec![0; 40];
        packet[0] = 0x60;
        packet
    }

    fn socket_pair() -> (Utun, UnixDatagram) {
        // Exercise the datagram adapter without allocating a utun or root access.
        let (local, peer) = UnixDatagram::pair().unwrap();
        local.set_nonblocking(true).unwrap();
        (
            Utun {
                fd: local.into(),
                name: "utun-test".into(),
            },
            peer,
        )
    }

    #[test]
    fn utun_header_uses_network_order_and_matches_ip_family() {
        assert_eq!(
            packet_family(&packet4()).unwrap().to_be_bytes(),
            [0, 0, 0, 2]
        );
        assert_eq!(
            packet_family(&packet6()).unwrap().to_be_bytes(),
            [0, 0, 0, 30]
        );
        assert!(validate_family([0, 0, 0, 30], &packet4()).is_err());
        assert!(validate_family([2, 0, 0, 0], &packet4()).is_err());
        assert!(validate_family([0, 0, 0, 2], &packet4()).is_ok());
    }

    #[test]
    fn utun_rejects_invalid_ip_lengths_and_names() {
        for packet in [
            vec![],
            vec![0x45],
            vec![0x60; 39],
            vec![0x40; 20],
            vec![0x50; 20],
        ] {
            assert!(packet_family(&packet).is_err());
        }
        let mut packet = packet4();
        packet[3] = 21;
        assert!(packet_family(&packet).is_err());
        let mut packet = packet6();
        packet[5] = 1;
        assert!(packet_family(&packet).is_err());
        assert_eq!(interface_name(b"utun15\0", 7).unwrap(), "utun15");
        for (name, length) in [
            (b"utun\0".as_slice(), 5),
            (b"en0\0", 4),
            (b"utun1", 5),
            (b"utun1\0", 7),
        ] {
            assert!(interface_name(name, length).is_err());
        }
    }

    #[test]
    fn utun_datagrams_round_trip_without_root() {
        let (tun, peer) = socket_pair();
        for packet in [packet4(), packet6()] {
            tun.write_packet(&packet).unwrap();
            let mut framed = [0; 128];
            let count = peer.recv(&mut framed).unwrap();
            assert_eq!(&framed[4..count], &packet);
            assert_eq!(
                u32::from_be_bytes(framed[..4].try_into().unwrap()),
                packet_family(&packet).unwrap()
            );
            peer.send(&framed[..count]).unwrap();
            let mut received = [0; 128];
            let count = tun.read_packet(&mut received).unwrap();
            assert_eq!(&received[..count], &packet);
        }
        assert_eq!(
            tun.read_packet(&mut [0; 128]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn utun_drops_truncated_datagrams_without_panicking() {
        let (tun, peer) = socket_pair();
        let mut frame = (libc::AF_INET as u32).to_be_bytes().to_vec();
        frame.extend(packet4());
        peer.send(&frame).unwrap();
        assert_eq!(
            tun.read_packet(&mut [0; 8]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        peer.send(&[0, 0]).unwrap();
        assert_eq!(
            tun.read_packet(&mut [0; 8]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            tun.read_packet(&mut [0; 128]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            tun.read_packet(&mut []).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
