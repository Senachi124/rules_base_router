use crate::{
    config::Profile,
    engine::Engine,
    policy::{FlowIdentity, Policy},
};
use std::{
    ffi::{c_char, CStr, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
};

fn output(value: serde_json::Value) -> *mut c_char {
    CString::new(value.to_string())
        .expect("JSON has no NUL")
        .into_raw()
}
unsafe fn text<'a>(p: *const c_char) -> Result<&'a str, String> {
    if p.is_null() {
        return Err("Missing input".into());
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| "Invalid UTF-8".into())
}
fn json_result(f: impl FnOnce() -> Result<serde_json::Value, String>) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => output(serde_json::json!({"ok": true, "value": value})),
        Ok(Err(error)) => output(serde_json::json!({"ok": false, "error": error})),
        Err(_) => output(serde_json::json!({"ok": false, "error": "Core operation failed"})),
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_string_free(p: *mut c_char) {
    if !p.is_null() {
        drop(unsafe { CString::from_raw(p) });
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_profile_inspect(p: *const c_char) -> *mut c_char {
    json_result(|| {
        Ok(serde_json::to_value(Profile::parse(unsafe { text(p)? })?.summary()).unwrap())
    })
}
#[no_mangle]
pub unsafe extern "C" fn rb_policy_validate(p: *const c_char) -> *mut c_char {
    json_result(|| {
        let mut policy: Policy =
            serde_json::from_str(unsafe { text(p)? }).map_err(|_| "Invalid policy")?;
        policy.validate()?;
        Ok(serde_json::to_value(policy).unwrap())
    })
}
#[no_mangle]
pub unsafe extern "C" fn rb_policy_evaluate(p: *const c_char, f: *const c_char) -> *mut c_char {
    json_result(|| {
        let mut policy: Policy =
            serde_json::from_str(unsafe { text(p)? }).map_err(|_| "Invalid policy")?;
        policy.validate()?;
        let flow: FlowIdentity =
            serde_json::from_str(unsafe { text(f)? }).map_err(|_| "Invalid flow")?;
        Ok(serde_json::to_value(policy.evaluate(&flow)).unwrap())
    })
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_new(p: *const c_char, raw: bool) -> *mut Engine {
    catch_unwind(AssertUnwindSafe(|| {
        unsafe { text(p) }
            .and_then(Profile::parse)
            .map(|p| Box::into_raw(Box::new(Engine::new(p, raw))))
            .unwrap_or(ptr::null_mut())
    }))
    .unwrap_or(ptr::null_mut())
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_free(p: *mut Engine) {
    if !p.is_null() {
        drop(unsafe { Box::from_raw(p) });
    }
}
unsafe fn run(p: *mut Engine, f: impl FnOnce(&mut Engine) -> Result<isize, String>) -> isize {
    if p.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| f(unsafe { &mut *p }).unwrap_or(-1))).unwrap_or(-1)
}
unsafe fn bytes<'a>(p: *const u8, len: usize) -> Result<&'a [u8], String> {
    if len > 65535 || (p.is_null() && len > 0) {
        return Err("Invalid buffer".into());
    }
    if len == 0 {
        Ok(&[])
    } else {
        Ok(unsafe { std::slice::from_raw_parts(p, len) })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_start(p: *mut Engine) -> isize {
    unsafe {
        run(p, |e| {
            e.start();
            Ok(0)
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_tick(p: *mut Engine, ms: i64) -> isize {
    unsafe {
        run(p, |e| {
            e.tick(ms);
            Ok(0)
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_receive(p: *mut Engine, data: *const u8, len: usize) -> isize {
    unsafe {
        run(p, |e| {
            e.receive(bytes(data, len)?);
            Ok(0)
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_feed_ip(p: *mut Engine, data: *const u8, len: usize) -> isize {
    unsafe {
        run(p, |e| {
            e.feed_ip(bytes(data, len)?)?;
            Ok(0)
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_open_tcp(
    p: *mut Engine,
    id: u64,
    address: *const c_char,
    port: u16,
) -> isize {
    unsafe {
        run(p, |e| {
            e.open_tcp(id, text(address)?.parse().map_err(|_| "Invalid IP")?, port)?;
            Ok(0)
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_tcp_write(
    p: *mut Engine,
    id: u64,
    data: *const u8,
    len: usize,
) -> isize {
    unsafe { run(p, |e| Ok(e.tcp_write(id, bytes(data, len)?)? as isize)) }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_tcp_eof(p: *mut Engine, id: u64) -> isize {
    unsafe {
        run(p, |e| {
            e.tcp_eof(id);
            Ok(0)
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_resume(p: *mut Engine, id: u64) -> isize {
    unsafe {
        run(p, |e| {
            e.resume(id);
            Ok(0)
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_open_udp(p: *mut Engine, id: u64) -> isize {
    unsafe {
        run(p, |e| {
            e.open_udp(id)?;
            Ok(0)
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_udp_send(
    p: *mut Engine,
    id: u64,
    address: *const c_char,
    port: u16,
    data: *const u8,
    len: usize,
) -> isize {
    unsafe {
        run(p, |e| {
            Ok(e.udp_send(
                id,
                text(address)?.parse().map_err(|_| "Invalid IP")?,
                port,
                bytes(data, len)?,
            )? as isize)
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_close(p: *mut Engine, id: u64) -> isize {
    unsafe {
        run(p, |e| {
            e.close(id);
            Ok(0)
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_handshake_age(p: *mut Engine) -> i64 {
    unsafe {
        run(p, |e| {
            Ok(e.handshake_age().map(|s| s as isize).unwrap_or(-1))
        }) as i64
    }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_flow_count(p: *mut Engine) -> isize {
    unsafe { run(p, |e| Ok(e.flow_count() as isize)) }
}
#[no_mangle]
pub unsafe extern "C" fn rb_engine_authenticated_rx_count(p: *mut Engine) -> u64 {
    if p.is_null() {
        0
    } else {
        unsafe { (&*p).authenticated_rx_count() }
    }
}

pub type Callback =
    unsafe extern "C" fn(*mut std::ffi::c_void, u32, u64, *const c_char, u16, *const u8, usize);
/// Callback buffers are borrowed only for the callback. Callers must copy them and must not re-enter.
#[no_mangle]
pub unsafe extern "C" fn rb_engine_drain(
    p: *mut Engine,
    callback: Option<Callback>,
    context: *mut std::ffi::c_void,
) -> isize {
    unsafe {
        run(p, |e| {
            let callback = callback.ok_or("Missing callback")?;
            while let Some(event) = e.pop_event() {
                let address = CString::new(event.address).unwrap();
                callback(
                    context,
                    event.kind,
                    event.flow,
                    address.as_ptr(),
                    event.port,
                    event.data.as_ptr(),
                    event.data.len(),
                );
            }
            Ok(0)
        })
    }
}
