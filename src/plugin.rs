use super::zabbix::rs_zabbix_register_parser;
use crate::detect::rs_zabbix_keywords_register;
use crate::log::rs_zabbix_log;
use std::ffi::CString;
use suricata::{SCLogError, SCLogNotice};
use suricata_sys::sys::{
    SCAppLayerPlugin, SCOutputJsonLogDirection, SCPlugin, SCPluginRegisterAppLayer, SC_API_VERSION,
    SC_PACKAGE_VERSION,
};

extern "C" fn zabbix_plugin_init() {
    SCLogNotice!("Initializing zabbix plugin");
    let plugin = SCAppLayerPlugin {
        name: b"zabbix\0".as_ptr() as *const libc::c_char,
        logname: b"JsonZabbixLog\0".as_ptr() as *const libc::c_char,
        confname: b"eve-log.zabbix\0".as_ptr() as *const libc::c_char,
        dir: SCOutputJsonLogDirection::LOG_DIR_PACKET as u8,
        Register: Some(rs_zabbix_register_parser),
        Logger: Some(rs_zabbix_log),
        KeywordsRegister: Some(rs_zabbix_keywords_register),
    };
    unsafe {
        if SCPluginRegisterAppLayer(Box::into_raw(Box::new(plugin))) != 0 {
            SCLogError!("Failed to register zabbix plugin");
        }
    }
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *const SCPlugin {
    // leak the CString
    let plugin_version =
        CString::new(env!("CARGO_PKG_VERSION")).unwrap().into_raw() as *const libc::c_char;
    let plugin = SCPlugin {
        version: SC_API_VERSION, // api version for suricata compatibility
        suricata_version: SC_PACKAGE_VERSION.as_ptr() as *const libc::c_char,
        name: b"zabbix\0".as_ptr() as *const libc::c_char,
        plugin_version,
        license: b"MIT\0".as_ptr() as *const libc::c_char,
        author: b"Philippe Antoine\0".as_ptr() as *const libc::c_char,
        Init: Some(zabbix_plugin_init),
    };
    Box::into_raw(Box::new(plugin))
}
