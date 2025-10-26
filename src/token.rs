use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Token 结构（泛型，支持自定义连接参数）
///
/// # 类型参数
/// * `P` - 连接参数类型，必须实现 `Serialize + Deserialize + Clone`
///
/// # 示例
/// ```
/// use serde::{Serialize, Deserialize};
/// use kestrel_protocol_security::Token;
///
/// #[derive(Clone, Serialize, Deserialize)]
/// struct MyConnectionParams {
///     max_packet_size: u32,
///     timeout_ms: u32,
/// }
///
/// let token: Token<MyConnectionParams> = Token {
///     client_addr_hash: 12345,
///     issued_at: 1000000,
///     expires_in: 3600,
///     connection_params: MyConnectionParams {
///         max_packet_size: 1350,
///         timeout_ms: 5000,
///     },
///     signature: [0; 32],
/// };
/// ```
#[derive(Debug, Clone)]
pub struct Token<P>
where
    P: Serialize + for<'de> Deserialize<'de> + Clone,
{
    /// 客户端地址指纹
    pub client_addr_hash: u64,
    /// 发行时间戳 (Unix时间，秒)
    pub issued_at: u64,
    /// 过期时间 (秒)
    pub expires_in: u32,
    /// 连接参数快照（使用 serde 序列化）
    pub connection_params: P,
    /// HMAC签名 (防篡改)
    pub signature: [u8; 32],
}

// 手动实现 Encode trait，使用 serde+bincode 处理 connection_params
impl<P> Encode for Token<P>
where
    P: Serialize + for<'de> Deserialize<'de> + Clone,
{
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        // 编码各个字段
        Encode::encode(&self.client_addr_hash, encoder)?;
        Encode::encode(&self.issued_at, encoder)?;
        Encode::encode(&self.expires_in, encoder)?;
        
        // 先使用 serde 将 connection_params 序列化为字节
        let params_bytes = bincode::serde::encode_to_vec(
            &self.connection_params,
            bincode::config::standard(),
        )
        .map_err(|e| bincode::error::EncodeError::OtherString(e.to_string()))?;
        
        // 编码字节长度和内容
        Encode::encode(&params_bytes.len(), encoder)?;
        Encode::encode(&params_bytes, encoder)?;
        
        Encode::encode(&self.signature, encoder)?;
        Ok(())
    }
}

// 手动实现 Decode trait，使用 serde+bincode 处理 connection_params
impl<P> Decode<()> for Token<P>
where
    P: Serialize + for<'de> Deserialize<'de> + Clone,
{
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        // 解码各个字段
        let client_addr_hash = Decode::decode(decoder)?;
        let issued_at = Decode::decode(decoder)?;
        let expires_in = Decode::decode(decoder)?;
        
        // 解码字节长度和内容
        let params_len: usize = Decode::decode(decoder)?;
        let params_bytes: Vec<u8> = Decode::decode(decoder)?;
        
        // 验证长度
        if params_bytes.len() != params_len {
            return Err(bincode::error::DecodeError::OtherString(
                "connection_params length mismatch".to_string()
            ));
        }
        
        // 使用 serde 反序列化 connection_params
        let (connection_params, _) = bincode::serde::decode_from_slice(
            &params_bytes,
            bincode::config::standard(),
        )
        .map_err(|e| bincode::error::DecodeError::OtherString(e.to_string()))?;
        
        let signature = Decode::decode(decoder)?;
        
        Ok(Token {
            client_addr_hash,
            issued_at,
            expires_in,
            connection_params,
            signature,
        })
    }
}


/// 计算客户端地址的哈希值
pub fn hash_address(addr: SocketAddr) -> u64 {
    let mut hasher = DefaultHasher::new();
    addr.hash(&mut hasher);
    hasher.finish()
}

/// 获取当前时间戳（Unix时间，秒）
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // 测试用的连接参数
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestConnectionParams {
        max_packet_size: u32,
        timeout_ms: u32,
    }

    impl Default for TestConnectionParams {
        fn default() -> Self {
            Self {
                max_packet_size: 1350,
                timeout_ms: 5000,
            }
        }
    }

    #[test]
    fn test_hash_address() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);

        assert_eq!(hash_address(addr1), hash_address(addr2));
        assert_ne!(hash_address(addr1), hash_address(addr3));
    }

    #[test]
    fn test_current_timestamp() {
        let ts1 = current_timestamp();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let ts2 = current_timestamp();
        assert!(ts2 >= ts1);
    }

    #[test]
    fn test_token_serialization() {
        let token = Token {
            client_addr_hash: 12345,
            issued_at: current_timestamp(),
            expires_in: 86400,
            connection_params: TestConnectionParams::default(),
            signature: [0u8; 32],
        };

        let serialized = bincode::encode_to_vec(&token, bincode::config::standard()).unwrap();
        let (deserialized, _): (Token<TestConnectionParams>, usize) = bincode::decode_from_slice(&serialized, bincode::config::standard()).unwrap();

        assert_eq!(token.client_addr_hash, deserialized.client_addr_hash);
        assert_eq!(token.issued_at, deserialized.issued_at);
        assert_eq!(token.expires_in, deserialized.expires_in);
        assert_eq!(token.connection_params, deserialized.connection_params);
    }

    #[test]
    fn test_custom_connection_params() {
        // 测试自定义连接参数类型
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        struct CustomParams {
            custom_value: u64,
            custom_name: String,
        }

        let token: Token<CustomParams> = Token {
            client_addr_hash: 67890,
            issued_at: current_timestamp(),
            expires_in: 3600,
            connection_params: CustomParams {
                custom_value: 999,
                custom_name: "test".to_string(),
            },
            signature: [1u8; 32],
        };

        let serialized = bincode::encode_to_vec(&token, bincode::config::standard()).unwrap();
        let (deserialized, _): (Token<CustomParams>, usize) = 
            bincode::decode_from_slice(&serialized, bincode::config::standard()).unwrap();

        assert_eq!(token.client_addr_hash, deserialized.client_addr_hash);
        assert_eq!(token.connection_params, deserialized.connection_params);
    }
}

