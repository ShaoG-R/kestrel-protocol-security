# Security - Token 重放防护库

基于 HMAC-SHA256 的 Token 机制和重放攻击防护系统，专为 0-RTT 网络协议设计。

## 特性

- ✅ **HMAC-SHA256 签名**: 使用 `hmac` 和 `sha2` crate 实现强签名机制
- ✅ **重放攻击防护**: 基于 LRU 缓存的高效重放检测
- ✅ **多层验证**: 签名验证、过期检查、地址验证、重放检测
- ✅ **高性能**: LRU 缓存优化的时间窗口检测
- ✅ **二进制序列化**: 使用 bincode 2.0 高效序列化/反序列化

## 快速开始

### 添加依赖

```toml
[dependencies]
security = { path = "." }
```

### 基本使用

```rust
use security::{TokenGenerator, TokenValidator, ReplayDetector, ConnectionParams};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// 1. 服务端初始化
let secret_key = b"your_secret_key_should_be_random".to_vec();
let params = ConnectionParams {
    max_packet_size: 1350,
    timeout_ms: 5000,
};

let generator = TokenGenerator::new(secret_key.clone(), params);

// 2. 生成 Token（首次连接时）
let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
let token = generator.generate(client_addr);

// 3. 序列化 Token 用于网络传输
let token_bytes = bincode::encode_to_vec(&token, bincode::config::standard()).unwrap();

// 4. 客户端接收 Token 并在后续请求中携带

// 5. 服务端验证 Token（0-RTT 连接时）
let detector = ReplayDetector::new(3600, 1000); // 1小时窗口，缓存1000个
let mut validator = TokenValidator::new(secret_key, detector);

match validator.validate(&token, client_addr) {
    Ok(()) => println!("验证成功，允许 0-RTT 连接"),
    Err(e) => println!("验证失败: {}", e),
}
```

## 核心组件

### 1. Token 结构

```rust
pub struct Token {
    pub client_addr_hash: u64,     // 客户端地址指纹
    pub issued_at: u64,            // 发行时间戳（Unix时间，秒）
    pub expires_in: u32,           // 过期时间（秒）
    pub connection_params: ConnectionParams,  // 连接参数快照
    pub signature: [u8; 32],       // HMAC-SHA256 签名
}
```

### 2. TokenGenerator - Token 生成器

负责生成带有 HMAC-SHA256 签名的安全 Token。

```rust
let generator = TokenGenerator::new(secret_key, connection_params);
let token = generator.generate(client_addr);
```

### 3. TokenValidator - Token 验证器

执行完整的多层验证流程：

1. **签名验证**: 使用 HMAC-SHA256 验证 Token 完整性
2. **过期检查**: 确保 Token 在有效期内
3. **地址验证**: 验证请求来源与 Token 绑定的地址匹配
4. **重放检测**: 使用 ReplayDetector 检测重放攻击

```rust
let mut validator = TokenValidator::new(secret_key, replay_detector);
validator.validate(&token, client_addr)?;
```

### 4. ReplayDetector - 重放检测器

使用 LRU 缓存实现高效的重放攻击检测：

```rust
let detector = ReplayDetector::new(
    time_window,  // 时间窗口（秒）
    cache_size    // LRU 缓存大小
);
```

**工作原理**：
- 检查 Token 是否在时间窗口内
- 使用 LRU 缓存记录已使用的 Token
- 自动驱逐过期的缓存条目

## 安全特性

### 1. 防篡改

Token 使用 HMAC-SHA256 签名，任何篡改都会被检测：

```rust
let mut tampered_token = token.clone();
tampered_token.expires_in = 999999;  // 篡改数据

validator.validate(&tampered_token, addr)  // 返回 InvalidSignature 错误
```

### 2. 防重放

同一个 Token 只能使用一次：

```rust
validator.validate(&token, addr)?;  // 第一次：成功
validator.validate(&token, addr)    // 第二次：返回 Replay 错误
```

### 3. 地址绑定

Token 与客户端地址绑定，无法被其他地址使用：

```rust
let token = generator.generate(addr1);
validator.validate(&token, addr2)  // 返回 AddressMismatch 错误
```

### 4. 时间窗口

Token 有明确的有效期和时间窗口限制：

```rust
// Token 默认 24 小时有效
// ReplayDetector 可配置时间窗口（如 1 小时）
```

## 错误类型

```rust
pub enum TokenError {
    InvalidSignature,   // 签名无效（篡改检测）
    Expired,           // Token 已过期
    AddressMismatch,   // 客户端地址不匹配
    Replay,            // 检测到重放攻击
    SerializationError, // 序列化错误
}
```

## 运行测试

```bash
# 运行所有单元测试
cargo test

# 运行集成测试
cargo test --test '*'

# 查看测试覆盖详情
cargo test -- --nocapture
```

## 运行示例

```bash
# 运行 0-RTT 协议演示
cargo run --example zero_rtt_demo
```

示例展示了以下场景：
1. 服务端初始化和 Token 生成
2. 客户端 0-RTT 连接验证
3. 重放攻击检测
4. 地址欺骗检测
5. 数据篡改检测
6. 多客户端并发连接

## 性能考虑

### LRU 缓存配置

```rust
// 根据预期连接数配置缓存大小
let detector = ReplayDetector::new(
    3600,   // 1小时时间窗口
    10000   // 缓存 10000 个 Token
);
```

**建议配置**：
- **低流量场景**：缓存 1,000 - 10,000
- **中等流量**：缓存 10,000 - 100,000
- **高流量场景**：缓存 100,000+ 或使用分布式缓存

### 时间窗口选择

```rust
// 时间窗口影响安全性和内存使用
let detector = ReplayDetector::new(
    3600,    // 1小时：平衡安全性和性能
    // 1800,  // 30分钟：更严格但需更频繁重连
    // 86400, // 24小时：更宽松但占用更多内存
    cache_size
);
```

## 0-RTT 协议集成

### 典型流程

```
1. 客户端首次连接
   ├─> 服务端生成 Token
   └─> 返回 Token 给客户端

2. 客户端后续连接（0-RTT）
   ├─> 携带 Token 发起连接
   ├─> 服务端验证 Token
   │   ├─ 签名验证 ✓
   │   ├─ 过期检查 ✓
   │   ├─ 地址验证 ✓
   │   └─ 重放检测 ✓
   └─> 立即处理请求（0-RTT）

3. Token 过期或被使用
   └─> 客户端重新请求新 Token
```

### 接口设计

```rust
// 服务端接口
pub trait ZeroRTTServer {
    fn handle_first_connection(&mut self, addr: SocketAddr) -> Token;
    fn handle_zero_rtt_connection(&mut self, token: &Token, addr: SocketAddr) -> Result<(), TokenError>;
}

// 实现示例
impl ZeroRTTServer for MyServer {
    fn handle_first_connection(&mut self, addr: SocketAddr) -> Token {
        self.token_generator.generate(addr)
    }

    fn handle_zero_rtt_connection(&mut self, token: &Token, addr: SocketAddr) -> Result<(), TokenError> {
        self.token_validator.validate(token, addr)
    }
}
```

## 技术细节

### HMAC-SHA256 实现

- 使用 `hmac` crate (0.12) 和 `sha2` crate (0.10)
- 256位（32字节）签名输出
- 密钥可以是任意长度（建议 ≥32 字节）

### 序列化格式

- 使用 `bincode` 2.0 进行高效二进制序列化
- Token 大小约 57 字节（取决于 ConnectionParams）
- 适合在网络中高效传输

### LRU 缓存

- 使用 `lru` crate (0.16.2) 实现
- O(1) 查找和插入性能
- 自动驱逐最久未使用的条目

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

