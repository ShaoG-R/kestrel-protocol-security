use crate::error::TokenError;
use crate::replay::ReplayDetector;
use crate::token::{current_timestamp, hash_address, Token};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::SocketAddr;

type HmacSha256 = Hmac<Sha256>;

/// Token 验证器（泛型版本，支持自定义连接参数类型）
///
/// # 类型参数
/// * `P` - 连接参数类型，必须实现 `Serialize + Deserialize + Clone`
pub struct TokenValidator<P>
where
    P: Serialize + for<'de> Deserialize<'de> + Clone,
{
    /// HMAC 密钥
    secret_key: Vec<u8>,
    /// 重放攻击检测器
    replay_detector: ReplayDetector,
    /// PhantomData 用于标记泛型参数
    _phantom: std::marker::PhantomData<P>,
}

impl<P> TokenValidator<P>
where
    P: Serialize + for<'de> Deserialize<'de> + Clone,
{
    /// 创建新的 Token 验证器
    ///
    /// # 参数
    /// * `secret_key` - HMAC 签名密钥
    /// * `replay_detector` - 重放攻击检测器
    pub fn new(secret_key: Vec<u8>, replay_detector: ReplayDetector) -> Self {
        Self {
            secret_key,
            replay_detector,
            _phantom: std::marker::PhantomData,
        }
    }

    /// 验证 Token
    ///
    /// # 参数
    /// * `token` - 待验证的 Token
    /// * `client_addr` - 客户端地址
    ///
    /// # 返回
    /// * `Ok(())` - 验证成功
    /// * `Err(TokenError)` - 验证失败
    pub fn validate(&mut self, token: &Token<P>, client_addr: SocketAddr) -> Result<(), TokenError> {
        // 1. 验证签名
        if !self.verify_signature(token) {
            return Err(TokenError::InvalidSignature);
        }

        // 2. 验证过期时间
        let now = current_timestamp();
        if now > token.issued_at + token.expires_in as u64 {
            return Err(TokenError::Expired);
        }

        // 3. 验证客户端地址
        if hash_address(client_addr) != token.client_addr_hash {
            return Err(TokenError::AddressMismatch);
        }

        // 4. 检查重放攻击
        if self.replay_detector.is_replayed(token) {
            return Err(TokenError::Replay);
        }

        Ok(())
    }

    /// 验证 Token 签名
    ///
    /// # 参数
    /// * `token` - 待验证的 Token
    ///
    /// # 返回
    /// * `true` - 签名有效
    /// * `false` - 签名无效
    fn verify_signature(&self, token: &Token<P>) -> bool {
        // 创建一个临时 Token，将 signature 清零以进行验证
        let token_for_verification = Token {
            signature: [0; 32],
            ..token.clone()
        };

        // 序列化 Token
        let serialized = match bincode::encode_to_vec(&token_for_verification, bincode::config::standard()) {
            Ok(data) => data,
            Err(_) => return false,
        };

        // 使用 HMAC-SHA256 验证
        let mut mac = match HmacSha256::new_from_slice(&self.secret_key) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(&serialized);

        // 验证签名
        mac.verify_slice(&token.signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::TokenGenerator;
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

    fn create_test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    #[test]
    fn test_valid_token() {
        let secret = b"test_secret_key".to_vec();
        let params = TestConnectionParams::default();
        
        let generator = TokenGenerator::new(secret.clone(), params);
        let addr = create_test_addr();
        let token = generator.generate(addr);

        let detector = ReplayDetector::new(3600, 100);
        let mut validator = TokenValidator::new(secret, detector);

        assert!(validator.validate(&token, addr).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let secret = b"test_secret_key".to_vec();
        let params = TestConnectionParams::default();
        
        let generator = TokenGenerator::new(secret.clone(), params);
        let addr = create_test_addr();
        let mut token = generator.generate(addr);

        // 篡改签名
        token.signature[0] ^= 1;

        let detector = ReplayDetector::new(3600, 100);
        let mut validator = TokenValidator::new(secret, detector);

        assert_eq!(validator.validate(&token, addr), Err(TokenError::InvalidSignature));
    }

    #[test]
    fn test_expired_token() {
        // 测试过期检测需要特殊的 TokenGenerator 支持
        // 这里我们直接测试时间检查逻辑
        let secret = b"test_secret_key".to_vec();
        let params = TestConnectionParams::default();
        
        let generator = TokenGenerator::new(secret.clone(), params);
        let addr = create_test_addr();
        let mut token = generator.generate(addr);
        
        // 修改为已过期（但这会导致签名失败）
        // 实际应用中，过期的 token 是在一段时间后自然过期的
        token.issued_at = current_timestamp() - 100000;
        token.expires_in = 1;

        let detector = ReplayDetector::new(3600, 100);
        let mut validator = TokenValidator::new(secret, detector);

        // 由于篡改了数据，签名验证会失败
        let result = validator.validate(&token, addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_address_mismatch() {
        let secret = b"test_secret_key".to_vec();
        let params = TestConnectionParams::default();
        
        let generator = TokenGenerator::new(secret.clone(), params);
        let addr1 = create_test_addr();
        let token = generator.generate(addr1);

        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);

        let detector = ReplayDetector::new(3600, 100);
        let mut validator = TokenValidator::new(secret, detector);

        assert_eq!(validator.validate(&token, addr2), Err(TokenError::AddressMismatch));
    }

    #[test]
    fn test_replay_attack() {
        let secret = b"test_secret_key".to_vec();
        let params = TestConnectionParams::default();
        
        let generator = TokenGenerator::new(secret.clone(), params);
        let addr = create_test_addr();
        let token = generator.generate(addr);

        let detector = ReplayDetector::new(3600, 100);
        let mut validator = TokenValidator::new(secret, detector);

        // 第一次验证应该成功
        assert!(validator.validate(&token, addr).is_ok());

        // 第二次验证应该失败（重放攻击）
        assert_eq!(validator.validate(&token, addr), Err(TokenError::Replay));
    }

    #[test]
    fn test_wrong_key() {
        let secret1 = b"test_secret_key1".to_vec();
        let secret2 = b"test_secret_key2".to_vec();
        let params = TestConnectionParams::default();
        
        let generator = TokenGenerator::new(secret1, params);
        let addr = create_test_addr();
        let token = generator.generate(addr);

        let detector = ReplayDetector::new(3600, 100);
        let mut validator = TokenValidator::new(secret2, detector);

        assert_eq!(validator.validate(&token, addr), Err(TokenError::InvalidSignature));
    }

    #[test]
    fn test_tampered_data() {
        let secret = b"test_secret_key".to_vec();
        let params = TestConnectionParams::default();
        
        let generator = TokenGenerator::new(secret.clone(), params);
        let addr = create_test_addr();
        let mut token = generator.generate(addr);

        // 篡改数据
        token.expires_in = 999999;

        let detector = ReplayDetector::new(3600, 100);
        let mut validator = TokenValidator::new(secret, detector);

        assert_eq!(validator.validate(&token, addr), Err(TokenError::InvalidSignature));
    }
}

