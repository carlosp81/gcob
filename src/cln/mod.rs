pub(crate) mod client;

pub(crate) mod cln_api {
    #![allow(clippy::enum_variant_names)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/cln.rs"));
}
