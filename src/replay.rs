use crate::token::{current_timestamp, Token};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;

/// 重放攻击检测器
pub struct ReplayDetector {
    /// Token 时间窗口 (秒)
    time_window: u64,
    /// 已使用的 Token 缓存 (TokenHash -> 使用时间)
    used_tokens: LruCache<u64, u64>,
}

impl ReplayDetector {
    /// 创建新的重放检测器
    ///
    /// # 参数
    /// * `time_window` - Token 有效时间窗口（秒）
    /// * `cache_size` - LRU 缓存大小
    pub fn new(time_window: u64, cache_size: usize) -> Self {
        Self {
            time_window,
            used_tokens: LruCache::new(NonZeroUsize::new(cache_size).unwrap()),
        }
    }

    /// 检测 Token 是否为重放攻击
    ///
    /// # 返回
    /// * `true` - 是重放攻击
    /// * `false` - 不是重放攻击
    pub fn is_replayed<P>(&mut self, token: &Token<P>) -> bool
    where
        P: Serialize + for<'de> Deserialize<'de> + Clone,
    {
        let token_hash = self.hash_token(token);
        let now = current_timestamp();

        // 检查 Token 是否在有效时间窗口内
        if now < token.issued_at || now > token.issued_at + self.time_window {
            return true; // 过期或未来 Token 视为重放
        }

        // 检查是否已使用
        if let Some(&_used_at) = self.used_tokens.get(&token_hash) {
            // Token 已被使用
            return true;
        }

        // 标记为已使用
        self.used_tokens.put(token_hash, now);

        false
    }

    /// 计算 Token 的哈希值
    fn hash_token<P>(&self, token: &Token<P>) -> u64
    where
        P: Serialize + for<'de> Deserialize<'de> + Clone,
    {
        let mut hasher = DefaultHasher::new();
        token.issued_at.hash(&mut hasher);
        token.client_addr_hash.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

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

    fn create_test_token(issued_at: u64, client_hash: u64) -> Token<TestConnectionParams> {
        Token {
            client_addr_hash: client_hash,
            issued_at,
            expires_in: 86400,
            connection_params: TestConnectionParams::default(),
            signature: [0u8; 32],
        }
    }

    #[test]
    fn test_new_detector() {
        let detector = ReplayDetector::new(3600, 100);
        assert_eq!(detector.time_window, 3600);
    }

    #[test]
    fn test_first_use_not_replayed() {
        let mut detector = ReplayDetector::new(3600, 100);
        let token = create_test_token(current_timestamp(), 12345);

        assert!(!detector.is_replayed(&token));
    }

    #[test]
    fn test_second_use_is_replayed() {
        let mut detector = ReplayDetector::new(3600, 100);
        let token = create_test_token(current_timestamp(), 12345);

        assert!(!detector.is_replayed(&token)); // 第一次使用
        assert!(detector.is_replayed(&token)); // 第二次使用，应该被检测为重放
    }

    #[test]
    fn test_expired_token_is_replayed() {
        let mut detector = ReplayDetector::new(3600, 100);
        let old_timestamp = current_timestamp() - 7200; // 2小时前
        let token = create_test_token(old_timestamp, 12345);

        assert!(detector.is_replayed(&token));
    }

    #[test]
    fn test_future_token_is_replayed() {
        let mut detector = ReplayDetector::new(3600, 100);
        let future_timestamp = current_timestamp() + 7200; // 2小时后
        let token = create_test_token(future_timestamp, 12345);

        assert!(detector.is_replayed(&token));
    }

    #[test]
    fn test_different_tokens_not_replayed() {
        let mut detector = ReplayDetector::new(3600, 100);
        let now = current_timestamp();
        let token1 = create_test_token(now, 12345);
        let token2 = create_test_token(now, 67890);

        assert!(!detector.is_replayed(&token1));
        assert!(!detector.is_replayed(&token2));
    }

    #[test]
    fn test_lru_cache_eviction() {
        let mut detector = ReplayDetector::new(3600, 2); // 只能缓存2个
        let now = current_timestamp();
        
        let token1 = create_test_token(now, 1);
        let token2 = create_test_token(now, 2);
        let token3 = create_test_token(now, 3);

        assert!(!detector.is_replayed(&token1));
        assert!(!detector.is_replayed(&token2));
        assert!(!detector.is_replayed(&token3)); // token1 应该被驱逐
        
        // token1 应该可以再次使用（因为被驱逐了）
        assert!(!detector.is_replayed(&token1));
    }
}

