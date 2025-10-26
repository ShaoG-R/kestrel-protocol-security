use crate::token::{current_timestamp, hash_address, Token};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::SocketAddr;

type HmacSha256 = Hmac<Sha256>;

/// Token 生成器（泛型版本，支持自定义连接参数类型）
///
/// # 类型参数
/// * `P` - 连接参数类型，必须实现 `Serialize + Deserialize + Clone`
///
/// # 示例
/// ```
/// use kestrel_protocol_security::TokenGenerator;
/// use serde::{Serialize, Deserialize};
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
///
/// #[derive(Clone, Serialize, Deserialize)]
/// struct MyParams {
///     max_packet_size: u32,
/// }
///
/// let secret_key = b"my_secret_key".to_vec();
/// let params = MyParams { max_packet_size: 1350 };
/// let generator = TokenGenerator::new(secret_key, params);
///
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
/// let token = generator.generate(addr);
/// ```
pub struct TokenGenerator<P>
where
    P: Serialize + for<'de> Deserialize<'de> + Clone,
{
    /// HMAC 密钥
    secret_key: Vec<u8>,
    /// 默认连接参数
    default_params: P,
}

impl<P> TokenGenerator<P>
where
    P: Serialize + for<'de> Deserialize<'de> + Clone,
{
    /// 创建新的 Token 生成器
    ///
    /// # 参数
    /// * `secret_key` - HMAC 签名密钥
    /// * `default_params` - 默认连接参数
    pub fn new(secret_key: Vec<u8>, default_params: P) -> Self {
        Self {
            secret_key,
            default_params,
        }
    }

    /// 生成新的 Token
    ///
    /// # 参数
    /// * `client_addr` - 客户端地址
    ///
    /// # 返回
    /// 生成的 Token
    pub fn generate(&self, client_addr: SocketAddr) -> Token<P> {
        let issued_at = current_timestamp();

        let mut token = Token {
            client_addr_hash: hash_address(client_addr),
            issued_at,
            expires_in: 86400, // 24小时
            connection_params: self.default_params.clone(),
            signature: [0; 32],
        };

        // 使用 HMAC-SHA256 签名
        let signature = self.sign(&token);
        token.signature = signature;

        token
    }

    /// 对 Token 进行签名
    ///
    /// # 参数
    /// * `token` - 待签名的 Token（signature 字段将被忽略）
    ///
    /// # 返回
    /// 32字节的 HMAC-SHA256 签名
    pub(crate) fn sign(&self, token: &Token<P>) -> [u8; 32] {
        // 创建一个临时 Token，将 signature 清零以进行签名
        let token_for_signing = Token {
            signature: [0; 32],
            ..token.clone()
        };

        // 序列化 Token
        let serialized = bincode::encode_to_vec(&token_for_signing, bincode::config::standard())
            .expect("Token serialization should not fail");

        // 使用 HMAC-SHA256 签名
        let mut mac = HmacSha256::new_from_slice(&self.secret_key)
            .expect("HMAC can take key of any size");
        mac.update(&serialized);
        let result = mac.finalize();

        // 将结果转换为 [u8; 32]
        let bytes = result.into_bytes();
        let mut signature = [0u8; 32];
        signature.copy_from_slice(&bytes);
        signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // 测试用的连接参数
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    fn test_generator_new() {
        let secret = b"test_secret_key".to_vec();
        let params = TestConnectionParams::default();
        let generator = TokenGenerator::new(secret, params);

        assert_eq!(generator.secret_key, b"test_secret_key");
    }

    #[test]
    fn test_generate_token() {
        let secret = b"test_secret_key".to_vec();
        let params = TestConnectionParams::default();
        let generator = TokenGenerator::new(secret, params);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let token = generator.generate(addr);

        assert_eq!(token.client_addr_hash, hash_address(addr));
        assert_eq!(token.expires_in, 86400);
        assert_ne!(token.signature, [0u8; 32]); // 签名应该不为空
    }

    #[test]
    fn test_same_address_same_signature() {
        let secret = b"test_secret_key".to_vec();
        let params = TestConnectionParams::default();
        let generator = TokenGenerator::new(secret, params.clone());

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // 创建两个时间戳相同的 token
        let token1 = Token {
            client_addr_hash: hash_address(addr),
            issued_at: 1000000,
            expires_in: 86400,
            connection_params: params.clone(),
            signature: [0; 32],
        };
        
        let sig1 = generator.sign(&token1);
        let sig2 = generator.sign(&token1);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_different_content_different_signature() {
        let secret = b"test_secret_key".to_vec();
        let params = TestConnectionParams::default();
        let generator = TokenGenerator::new(secret, params.clone());

        let token1 = Token {
            client_addr_hash: 12345,
            issued_at: 1000000,
            expires_in: 86400,
            connection_params: params.clone(),
            signature: [0; 32],
        };

        let token2 = Token {
            client_addr_hash: 67890, // 不同的地址哈希
            issued_at: 1000000,
            expires_in: 86400,
            connection_params: params,
            signature: [0; 32],
        };

        let sig1 = generator.sign(&token1);
        let sig2 = generator.sign(&token2);

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_different_key_different_signature() {
        let params = TestConnectionParams::default();
        let generator1 = TokenGenerator::new(b"key1".to_vec(), params.clone());
        let generator2 = TokenGenerator::new(b"key2".to_vec(), params.clone());

        let token = Token {
            client_addr_hash: 12345,
            issued_at: 1000000,
            expires_in: 86400,
            connection_params: params,
            signature: [0; 32],
        };

        let sig1 = generator1.sign(&token);
        let sig2 = generator2.sign(&token);

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_custom_params_generator() {
        // 测试使用自定义参数类型的生成器
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct CustomParams {
            buffer_size: usize,
            protocol_version: u8,
        }

        let secret = b"test_secret".to_vec();
        let custom_params = CustomParams {
            buffer_size: 2048,
            protocol_version: 2,
        };

        let generator = TokenGenerator::new(secret, custom_params);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);
        let token = generator.generate(addr);

        assert_eq!(token.connection_params.buffer_size, 2048);
        assert_eq!(token.connection_params.protocol_version, 2);
        assert_ne!(token.signature, [0u8; 32]);
    }
}

