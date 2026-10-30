use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use std::collections::VecDeque;

pub struct MemoryDevice {
    pub received: VecDeque<Vec<u8>>,
    pub sent: VecDeque<Vec<u8>>,
    pub mtu: usize,
}
pub struct Receive(pub Vec<u8>);
pub struct Transmit<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Receive {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
impl TxToken for Transmit<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        self.0.push_back(bytes);
        result
    }
}
impl Device for MemoryDevice {
    type RxToken<'a>
        = Receive
    where
        Self: 'a;
    type TxToken<'a>
        = Transmit<'a>
    where
        Self: 'a;
    fn receive(&mut self, _: Instant) -> Option<(Receive, Transmit<'_>)> {
        self.received
            .pop_front()
            .map(|p| (Receive(p), Transmit(&mut self.sent)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Transmit<'_>> {
        if self.sent.len() < 512 {
            Some(Transmit(&mut self.sent))
        } else {
            None
        }
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}
