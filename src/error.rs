use std::fmt;

/// Token 相关的错误类型
#[derive(Debug, Clone, PartialEq)]
pub enum TokenError {
    /// 签名无效
    InvalidSignature,
    /// Token 已过期
    Expired,
    /// 客户端地址不匹配
    AddressMismatch,
    /// 检测到重放攻击
    Replay,
    /// 序列化/反序列化错误
    SerializationError,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::InvalidSignature => write!(f, "Token 签名无效"),
            TokenError::Expired => write!(f, "Token 已过期"),
            TokenError::AddressMismatch => write!(f, "客户端地址不匹配"),
            TokenError::Replay => write!(f, "检测到重放攻击"),
            TokenError::SerializationError => write!(f, "序列化错误"),
        }
    }
}

impl std::error::Error for TokenError {}

