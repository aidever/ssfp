//! 共享：SYN 报文解析、OS 家族、出口指纹模板。

pub mod syn;
pub mod template;

pub use syn::{SynFields, parse_syn};
pub use template::{Family, Template};
