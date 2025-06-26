use crate::zabbix::{ZabbixTransaction, ALPROTO_ZABBIX};
use std::os::raw::{c_int, c_void};
use suricata::cast_pointer;
use suricata::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use suricata::detect::uint::{DetectUintData, SCDetectU8Match, SCDetectU8Parse};
use suricata::detect::{SIGMATCH_INFO_STICKY_BUFFER, SIGMATCH_NOOPT};
use suricata::SCLogNotice;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectHelperBufferRegister, SCDetectHelperKeywordRegister,
    SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList, SCSigTableAppLiteElmt, SigMatchCtx,
    Signature,
};

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_keywords_register() {
    SCLogNotice!("registering Zabbix keywords");
    zabbix_register_flags_keyword();
    zabbix_register_data_keyword();
}

static mut G_ZABBIX_FLAGS_KWID: u16 = 0;
static mut G_ZABBIX_FLAGS_BUFFER_ID: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_flags_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const std::os::raw::c_char,
) -> c_int {
    let ctx = SCDetectU8Parse(raw) as *mut std::os::raw::c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_ZABBIX_FLAGS_KWID,
        ctx as *mut SigMatchCtx,
        G_ZABBIX_FLAGS_BUFFER_ID,
    )
    .is_null()
    {
        rs_zabbix_flags_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_flags_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, ZabbixTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Match(tx.zabbix.flags, ctx)
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_flags_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    // Just unbox...
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    std::mem::drop(Box::from_raw(ctx));
}

fn zabbix_register_flags_keyword() {
    let kw = SCSigTableAppLiteElmt {
        name: b"zabbix.flags\0".as_ptr() as *const libc::c_char,
        desc: b"match on zabbix header flags\0".as_ptr() as *const libc::c_char,
        url: b"\0".as_ptr() as *const libc::c_char,
        flags: 0,
        AppLayerTxMatch: Some(rs_zabbix_flags_match),
        Setup: Some(rs_zabbix_flags_setup),
        Free: Some(rs_zabbix_flags_free),
    };
    unsafe {
        G_ZABBIX_FLAGS_KWID = SCDetectHelperKeywordRegister(&kw);
        G_ZABBIX_FLAGS_BUFFER_ID = SCDetectHelperBufferRegister(
            b"zabbix_flags\0".as_ptr() as *const libc::c_char,
            ALPROTO_ZABBIX,
            STREAM_TOSERVER | STREAM_TOCLIENT,
        );
    }
}

static mut G_ZABBIX_DATA_BUFID: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_data_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectBufferSetActiveList(de, s, G_ZABBIX_DATA_BUFID) < 0 {
        return -1;
    }
    if SCDetectSignatureSetAppProto(s, ALPROTO_ZABBIX) != 0 {
        return -1;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_get_data(
    tx: *const c_void,
    _flow_flags: u8,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, ZabbixTransaction);
    *buffer = tx.zabbix.data.as_ptr();
    *buffer_len = tx.zabbix.data.len() as u32;
    true
}

pub(super) fn zabbix_register_data_keyword() {
    let kw = SCSigTableAppLiteElmt {
        name: b"zabbix.data\0".as_ptr() as *const libc::c_char,
        desc: b"match on zabbix data\0".as_ptr() as *const libc::c_char,
        url: b"\0".as_ptr() as *const libc::c_char,
        Setup: Some(rs_zabbix_data_setup),
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    unsafe {
        SCDetectHelperKeywordRegister(&kw);
        G_ZABBIX_DATA_BUFID = SCDetectHelperBufferMpmRegister(
            b"zabbix_data\0".as_ptr() as *const libc::c_char,
            b"zabbix data\0".as_ptr() as *const libc::c_char,
            ALPROTO_ZABBIX,
            STREAM_TOSERVER | STREAM_TOCLIENT,
            Some(rs_zabbix_get_data),
        );
    }
}
