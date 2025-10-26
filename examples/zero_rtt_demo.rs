//! # 0-RTT 协议 Token 机制演示
//!
//! 本示例演示了如何在 0-RTT 网络协议中使用 Token 机制进行安全认证和重放防护。
//!
//! 运行: cargo run --example zero_rtt_demo

use kestrel_protocol_security::{ReplayDetector, Token, TokenGenerator, TokenValidator};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// 示例用的连接参数
#[derive(Clone, Serialize, Deserialize)]
struct ConnectionParams {
    max_packet_size: u32,
    timeout_ms: u32,
}

fn main() {
    println!("=== 0-RTT Token 重放防护演示 ===\n");

    // 1. 服务端配置
    println!("1. 服务端初始化");
    let server_secret = b"server_master_secret_key_should_be_random".to_vec();
    let connection_params = ConnectionParams {
        max_packet_size: 1350,
        timeout_ms: 5000,
    };

    let token_generator = TokenGenerator::new(server_secret.clone(), connection_params);
    let replay_detector = ReplayDetector::new(86400, 10000); // 24小时，缓存10000个token
    let mut token_validator = TokenValidator::new(server_secret, replay_detector);

    println!("   ✓ Token 生成器已初始化");
    println!("   ✓ Token 验证器已初始化");
    println!("   ✓ 重放检测器已初始化 (时间窗口: 24小时, 缓存: 10000)\n");

    // 2. 场景1: 客户端首次连接
    println!("2. 场景1: 客户端首次连接");
    let client1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 50000);
    println!("   客户端地址: {}", client1_addr);

    let token1 = token_generator.generate(client1_addr);
    println!("   ✓ 服务端生成 Token");
    println!("     - 发行时间: {}", token1.issued_at);
    println!("     - 有效期: {} 秒", token1.expires_in);
    println!("     - 客户端哈希: {}", token1.client_addr_hash);
    println!("     - 签名前8字节: {:02x?}...", &token1.signature[..8]);

    // 序列化 Token 用于网络传输
    let token_bytes = bincode::encode_to_vec(&token1, bincode::config::standard()).unwrap();
    println!("   ✓ Token 序列化为 {} 字节用于网络传输\n", token_bytes.len());

    // 3. 场景2: 客户端使用 Token 进行 0-RTT 连接
    println!("3. 场景2: 客户端使用 Token 进行 0-RTT 连接");
    
    // 客户端发送 Token
    let (received_token, _): (Token<ConnectionParams>, usize) = 
        bincode::decode_from_slice(&token_bytes, bincode::config::standard()).unwrap();
    println!("   ✓ 服务端接收并反序列化 Token");

    // 服务端验证 Token
    match token_validator.validate(&received_token, client1_addr) {
        Ok(()) => {
            println!("   ✓ Token 验证成功！");
            println!("     - 签名有效");
            println!("     - 未过期");
            println!("     - 地址匹配");
            println!("     - 非重放攻击");
            println!("   → 允许 0-RTT 连接\n");
        }
        Err(e) => {
            println!("   ✗ Token 验证失败: {}\n", e);
        }
    }

    // 4. 场景3: 攻击者尝试重放 Token
    println!("4. 场景3: 攻击者尝试重放同一个 Token");
    println!("   攻击者地址: {}", client1_addr);
    
    match token_validator.validate(&received_token, client1_addr) {
        Ok(()) => {
            println!("   ✗ 重放攻击未被检测到！\n");
        }
        Err(e) => {
            println!("   ✓ 成功检测到重放攻击！");
            println!("   ✓ 错误信息: {}", e);
            println!("   → 拒绝连接\n");
        }
    }

    // 5. 场景4: 攻击者尝试使用 Token 连接到不同地址
    println!("5. 场景4: 攻击者使用窃取的 Token 从不同地址连接");
    let attacker_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 60000);
    println!("   攻击者地址: {}", attacker_addr);

    // 生成新的 token 用于测试（因为之前的已被使用）
    let token_for_attack = token_generator.generate(client1_addr);
    
    match token_validator.validate(&token_for_attack, attacker_addr) {
        Ok(()) => {
            println!("   ✗ 地址欺骗未被检测到！\n");
        }
        Err(e) => {
            println!("   ✓ 成功检测到地址不匹配！");
            println!("   ✓ 错误信息: {}", e);
            println!("   → 拒绝连接\n");
        }
    }

    // 6. 场景5: 攻击者尝试篡改 Token
    println!("6. 场景5: 攻击者尝试篡改 Token 数据");
    let mut tampered_token = token_generator.generate(client1_addr);
    tampered_token.expires_in = 999999; // 篡改过期时间
    println!("   篡改内容: 修改 expires_in 从 86400 到 999999");

    match token_validator.validate(&tampered_token, client1_addr) {
        Ok(()) => {
            println!("   ✗ 数据篡改未被检测到！\n");
        }
        Err(e) => {
            println!("   ✓ 成功检测到数据篡改！");
            println!("   ✓ 错误信息: {}", e);
            println!("   → 拒绝连接\n");
        }
    }

    // 7. 场景6: 多个合法客户端
    println!("7. 场景6: 多个合法客户端并发连接");
    let clients = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8081),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8082),
    ];

    for (i, client_addr) in clients.iter().enumerate() {
        let token = token_generator.generate(*client_addr);
        match token_validator.validate(&token, *client_addr) {
            Ok(()) => {
                println!("   ✓ 客户端 {} ({}) 验证成功", i + 1, client_addr);
            }
            Err(e) => {
                println!("   ✗ 客户端 {} ({}) 验证失败: {}", i + 1, client_addr, e);
            }
        }
    }

    println!("\n=== 演示完成 ===");
}

