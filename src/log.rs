use crate::zabbix::ZabbixTransaction;
use suricata::cast_pointer;
use suricata::jsonbuilder::JsonError;
use suricata_sys::jsonbuilder::{
    SCJbClose, SCJbOpenObject, SCJbSetString, SCJbSetUint, SCJsonBuilder,
};

use std::ffi::CString;

// syntax sugar around C API of SCJsonBuilder to feel like a normal app-layer in log_template
pub struct SCJsonBuilderWrapper {
    inner: *mut SCJsonBuilder,
}

impl SCJsonBuilderWrapper {
    fn close(&mut self) -> Result<(), JsonError> {
        if unsafe { !SCJbClose(self.inner) } {
            return Err(JsonError::Memory);
        }
        Ok(())
    }
    fn open_object(&mut self, key: &str) -> Result<(), JsonError> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbOpenObject(self.inner, keyc.as_ptr()) } {
            return Err(JsonError::Memory);
        }
        Ok(())
    }
    fn set_string(&mut self, key: &str, val: &str) -> Result<(), JsonError> {
        let keyc = CString::new(key).unwrap();
        let valc = CString::new(val.escape_default().to_string()).unwrap();
        if unsafe { !SCJbSetString(self.inner, keyc.as_ptr(), valc.as_ptr()) } {
            return Err(JsonError::Memory);
        }
        Ok(())
    }
    fn set_uint(&mut self, key: &str, val: u64) -> Result<(), JsonError> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbSetUint(self.inner, keyc.as_ptr(), val) } {
            return Err(JsonError::Memory);
        }
        Ok(())
    }
}

fn log_zabbix(tx: &ZabbixTransaction, jb: &mut SCJsonBuilderWrapper) -> Result<(), JsonError> {
    jb.open_object("zabbix")?;
    jb.set_uint("flags", tx.zabbix.flags.into())?;
    //TODO make configurable
    if tx.zabbix.data.len() < 256 {
        jb.set_string("data", &String::from_utf8_lossy(&tx.zabbix.data))?;
    } else {
        jb.set_string("data", &String::from_utf8_lossy(&tx.zabbix.data[..256]))?;
    }
    jb.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_log(
    tx: *const std::os::raw::c_void,
    jb: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, ZabbixTransaction);
    let jb = cast_pointer!(jb, SCJsonBuilder);
    let mut jb = SCJsonBuilderWrapper { inner: jb };
    log_zabbix(tx, &mut jb).is_ok()
}
