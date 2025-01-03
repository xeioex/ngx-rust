use std::ffi::{c_char, c_void};
use std::ptr::addr_of;

use ngx::core;
use ngx::ffi::{
    nginx_version, ngx_command_t, ngx_conf_t, ngx_http_output_header_filter_pt, ngx_http_output_body_filter_pt,
    ngx_http_top_header_filter, ngx_http_top_body_filter, ngx_http_request_t, ngx_chain_t,
    ngx_http_module_t, ngx_int_t, ngx_str_t, ngx_module_t,  ngx_uint_t,
    NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF, NGX_RS_HTTP_LOC_CONF_OFFSET,
    NGX_RS_MODULE_SIGNATURE,
};
use ngx::http::*;
use ngx::{ngx_log_debug_http, ngx_null_command, ngx_string};

struct Module;

static mut NGX_HTTP_NEXT_HEADER_FILTER: ngx_http_output_header_filter_pt = None;
static mut NGX_HTTP_NEXT_BODY_FILTER: ngx_http_output_body_filter_pt = None;


impl HTTPModule for Module {
    type MainConf = ();
    type SrvConf = ();
    type LocConf = ModuleConfig;

    unsafe extern "C" fn postconfiguration(_cf: *mut ngx_conf_t) -> ngx_int_t {
        NGX_HTTP_NEXT_HEADER_FILTER = ngx_http_top_header_filter;
        ngx_http_top_header_filter = Some(ngx_http_html_header_filter);

        NGX_HTTP_NEXT_BODY_FILTER = ngx_http_top_body_filter;
        ngx_http_top_body_filter = Some(ngx_http_html_body_filter);

        core::Status::NGX_OK.into()
    }
}

#[derive(Debug, Default)]
struct ModuleConfig {
    enable: bool,
}

static mut NGX_HTTP_HTML_REWRITE_COMMANDS: [ngx_command_t; 2] = [
    ngx_command_t {
        name: ngx_string!("html_rewrite"),
        type_: (NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_html_commands_set_enable),
        conf: NGX_RS_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_null_command!(),
];

static NGX_HTTP_HTML_REWRITE_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: Some(Module::create_main_conf),
    init_main_conf: Some(Module::init_main_conf),
    create_srv_conf: Some(Module::create_srv_conf),
    merge_srv_conf: Some(Module::merge_srv_conf),
    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

// Generate the `ngx_modules` table with exported modules.
// This feature is required to build a 'cdylib' dynamic module outside of the NGINX buildsystem.
#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_html_rewrite_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), no_mangle)]
pub static mut ngx_http_html_rewrite_module: ngx_module_t = ngx_module_t {
    ctx_index: ngx_uint_t::MAX,
    index: ngx_uint_t::MAX,
    name: std::ptr::null_mut(),
    spare0: 0,
    spare1: 0,
    version: nginx_version as ngx_uint_t,
    signature: NGX_RS_MODULE_SIGNATURE.as_ptr() as *const c_char,

    ctx: &NGX_HTTP_HTML_REWRITE_MODULE_CTX as *const _ as *mut _,
    commands: unsafe { &NGX_HTTP_HTML_REWRITE_COMMANDS[0] as *const _ as *mut _ },
    type_: NGX_HTTP_MODULE as ngx_uint_t,

    init_master: None,
    init_module: None,
    init_process: None,
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,

    spare_hook0: 0,
    spare_hook1: 0,
    spare_hook2: 0,
    spare_hook3: 0,
    spare_hook4: 0,
    spare_hook5: 0,
    spare_hook6: 0,
    spare_hook7: 0,
};

impl Merge for ModuleConfig {
    fn merge(&mut self, prev: &ModuleConfig) -> Result<(), MergeConfigError> {
        if prev.enable {
            self.enable = true;
        };
        Ok(())
    }
}


extern "C" fn ngx_http_html_commands_set_enable(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut ModuleConfig) };
    let val = unsafe { (*((*(*cf).args).elts as *mut ngx_str_t).add(1)).to_str() };

    if val.len() == 2 && val.eq_ignore_ascii_case("on") {
        conf.enable = true;

    } else if val.len() == 3 && val.eq_ignore_ascii_case("off") {
        conf.enable = false;
    }

    std::ptr::null_mut()
}


extern "C" fn ngx_http_html_header_filter(r: *mut ngx_http_request_t) -> ngx_int_t {
    let request = unsafe { &mut Request::from_ngx_http_request(r) };
    let conf = unsafe { request.get_module_loc_conf::<ModuleConfig>(&*addr_of!(ngx_http_html_rewrite_module)) };
    let conf = conf.unwrap();
    if !conf.enable {
        return unsafe { NGX_HTTP_NEXT_HEADER_FILTER.unwrap()(r) }
    }

    ngx_log_debug_http!(request, "HTML rewrite module header filter");

    unsafe { NGX_HTTP_NEXT_HEADER_FILTER.unwrap()(r) }
}


extern "C" fn ngx_http_html_body_filter(r: *mut ngx_http_request_t, in_bufs: *mut ngx_chain_t) -> ngx_int_t {
    let request = unsafe { &mut Request::from_ngx_http_request(r) };
    let conf = unsafe { request.get_module_loc_conf::<ModuleConfig>(&*addr_of!(ngx_http_html_rewrite_module)) };
    let conf = conf.unwrap();
    if !conf.enable {
        return unsafe { NGX_HTTP_NEXT_BODY_FILTER.unwrap()(r, in_bufs) }
    }

    ngx_log_debug_http!(request, "HTML rewrite module body filter");

    unsafe { NGX_HTTP_NEXT_BODY_FILTER.unwrap()(r, in_bufs) }
}
