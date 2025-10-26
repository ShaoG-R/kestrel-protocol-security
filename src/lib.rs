//! # Security - Token 重放防护实现
//!
//! 本库实现了基于 HMAC-SHA256 的 Token 机制和重放攻击防护系统，
//! 用于 0-RTT 网络协议的安全认证。
//!
//! ## 主要功能
//!
//! - **Token 生成**: 使用 HMAC-SHA256 签名的安全 Token
//! - **Token 验证**: 多层验证机制（签名、过期、地址、重放）
//! - **重放检测**: 基于 LRU 缓存的高效重放攻击检测
//!
//! ## 使用示例
//!
//! ```rust
//! use kestrel_protocol_security::{TokenGenerator, TokenValidator, ReplayDetector};
//! use serde::{Serialize, Deserialize};
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//!
//! // 定义您自己的连接参数
//! #[derive(Clone, Serialize, Deserialize)]
//! struct ConnectionParams {
//!     max_packet_size: u32,
//!     timeout_ms: u32,
//! }
//!
//! // 服务端：生成 Token
//! let secret_key = b"your_secret_key".to_vec();
//! let params = ConnectionParams { max_packet_size: 1350, timeout_ms: 5000 };
//! let generator = TokenGenerator::new(secret_key.clone(), params);
//!
//! let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
//! let token = generator.generate(client_addr);
//!
//! // 客户端接收 Token 并在后续请求中携带
//!
//! // 服务端：验证 Token
//! let detector = ReplayDetector::new(3600, 1000); // 1小时时间窗口，缓存1000个token
//! let mut validator = TokenValidator::new(secret_key, detector);
//!
//! match validator.validate(&token, client_addr) {
//!     Ok(()) => println!("Token 验证成功"),
//!     Err(e) => println!("Token 验证失败: {}", e),
//! }
//! ```

pub mod error;
pub mod generator;
pub mod replay;
pub mod token;
pub mod validator;

// 重新导出主要类型
pub use error::TokenError;
pub use generator::TokenGenerator;
pub use replay::ReplayDetector;
pub use token::Token;
pub use validator::TokenValidator;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // 测试用的连接参数
    #[derive(Clone, Serialize, Deserialize)]
    struct ConnectionParams {
        max_packet_size: u32,
        timeout_ms: u32,
    }

    #[test]
    fn test_complete_flow() {
        // 1. 初始化
        let secret_key = b"test_secret_key_for_integration".to_vec();
        let params = ConnectionParams {
            max_packet_size: 1500,
            timeout_ms: 10000,
        };

        // 2. 服务端生成 Token
        let generator = TokenGenerator::new(secret_key.clone(), params);
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let token = generator.generate(client_addr);

        // 3. 服务端验证 Token
        let detector = ReplayDetector::new(3600, 100);
        let mut validator = TokenValidator::new(secret_key, detector);

        // 4. 验证应该成功
        assert!(validator.validate(&token, client_addr).is_ok());

        // 5. 重放攻击应该被检测
        assert_eq!(
            validator.validate(&token, client_addr),
            Err(TokenError::Replay)
        );
    }

    #[test]
    fn test_multiple_clients() {
        let secret_key = b"test_secret_key".to_vec();
        let params = ConnectionParams {
            max_packet_size: 1350,
            timeout_ms: 5000,
        };
        let generator = TokenGenerator::new(secret_key.clone(), params);

        let detector = ReplayDetector::new(3600, 100);
        let mut validator = TokenValidator::new(secret_key, detector);

        // 多个客户端
        let clients = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)), 8080),
        ];

        for client_addr in &clients {
            let token = generator.generate(*client_addr);
            assert!(validator.validate(&token, *client_addr).is_ok());
        }
    }

    #[test]
    fn test_0rtt_protocol_interface() {
        // 模拟 0-RTT 协议使用场景

        // 服务端配置
        let server_secret = b"server_master_secret".to_vec();
        let connection_params = ConnectionParams {
            max_packet_size: 1350,
            timeout_ms: 5000,
        };

        // 服务端组件
        let token_generator = TokenGenerator::new(server_secret.clone(), connection_params);
        let replay_detector = ReplayDetector::new(86400, 10000); // 24小时，缓存10000个
        let mut token_validator = TokenValidator::new(server_secret, replay_detector);

        // 场景1: 客户端首次连接
        let client1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let token1 = token_generator.generate(client1_addr);

        // 客户端保存 token 并在下次连接时使用

        // 场景2: 客户端使用 token 进行 0-RTT 连接
        assert!(token_validator.validate(&token1, client1_addr).is_ok());

        // 场景3: 攻击者尝试重放 token
        assert_eq!(
            token_validator.validate(&token1, client1_addr),
            Err(TokenError::Replay)
        );

        // 场景4: 攻击者尝试使用 token 连接到其他地址
        let attacker_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 50001);
        assert_eq!(
            token_validator.validate(&token1, attacker_addr),
            Err(TokenError::AddressMismatch)
        );
    }

    #[test]
    fn test_token_serialization_for_network() {
        let secret_key = b"test_secret".to_vec();
        let params = ConnectionParams {
            max_packet_size: 1350,
            timeout_ms: 5000,
        };
        let generator = TokenGenerator::new(secret_key, params);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let token = generator.generate(addr);

        // 序列化（用于网络传输）
        let serialized = bincode::encode_to_vec(&token, bincode::config::standard()).expect("序列化失败");

        // 反序列化（接收端）
        let (deserialized, _): (Token<ConnectionParams>, usize) = bincode::decode_from_slice(&serialized, bincode::config::standard()).expect("反序列化失败");

        // 验证数据完整性
        assert_eq!(token.client_addr_hash, deserialized.client_addr_hash);
        assert_eq!(token.issued_at, deserialized.issued_at);
        assert_eq!(token.expires_in, deserialized.expires_in);
        assert_eq!(token.signature, deserialized.signature);
    }
}
