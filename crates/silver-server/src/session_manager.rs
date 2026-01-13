//! Session Manager
//!
//! Manages active VPN sessions with cleanup and statistics.

use silver_protocol::{Session, SessionId, SessionStats};
use silver_timing::{SilverScheduler, TrafficShaper};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Manages all active sessions
pub struct SessionManager {
    /// Sessions indexed by remote address
    sessions: HashMap<SocketAddr, ManagedSession>,
    /// Maximum number of sessions
    max_sessions: usize,
    /// Total sessions created (lifetime counter)
    total_created: u64,
    /// Session timeout
    session_timeout: Duration,
}

/// A managed session with metadata
pub struct ManagedSession {
    /// The protocol session
    pub session: Session,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Traffic shaper for this session
    pub shaper: TrafficShaper,
    /// Timing scheduler for this session
    pub scheduler: SilverScheduler,
    /// Creation time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
}

impl ManagedSession {
    /// Create a new managed session
    pub fn new(session: Session, remote_addr: SocketAddr, target_bandwidth: u64) -> Self {
        Self {
            session,
            remote_addr,
            shaper: TrafficShaper::new(target_bandwidth),
            scheduler: SilverScheduler::new(10_000), // 10ms base
            created_at: Instant::now(),
            last_activity: Instant::now(),
        }
    }

    /// Update activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        self.session.touch();
    }

    /// Get session age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get idle time
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Check if session has expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.idle_time() > timeout
    }

    /// Get session ID
    pub fn id(&self) -> SessionId {
        self.session.id()
    }

    /// Get statistics
    pub fn stats(&self) -> ManagedSessionStats {
        ManagedSessionStats {
            session_stats: SessionStats::from(&self.session),
            remote_addr: self.remote_addr,
            shaper_stats: self.shaper.stats(),
            age_secs: self.age().as_secs(),
            idle_secs: self.idle_time().as_secs(),
        }
    }
}

/// Statistics for a managed session
#[derive(Debug, Clone)]
pub struct ManagedSessionStats {
    /// Protocol session stats
    pub session_stats: SessionStats,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Shaper stats
    pub shaper_stats: silver_timing::ShapingStats,
    /// Age in seconds
    pub age_secs: u64,
    /// Idle time in seconds
    pub idle_secs: u64,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::with_capacity(max_sessions),
            max_sessions,
            total_created: 0,
            session_timeout: Duration::from_secs(120),
        }
    }

    /// Create with custom timeout
    pub fn with_timeout(max_sessions: usize, timeout: Duration) -> Self {
        Self {
            sessions: HashMap::with_capacity(max_sessions),
            max_sessions,
            total_created: 0,
            session_timeout: timeout,
        }
    }

    /// Add a new session
    pub fn add_session(&mut self, addr: SocketAddr, session: Session) -> bool {
        if self.sessions.len() >= self.max_sessions {
            // Try to cleanup expired sessions first
            self.cleanup_expired();

            if self.sessions.len() >= self.max_sessions {
                return false;
            }
        }

        let managed = ManagedSession::new(session, addr, 10_000_000); // 10 MB/s default
        self.sessions.insert(addr, managed);
        self.total_created += 1;
        true
    }

    /// Get a session by address
    pub fn get_session(&self, addr: &SocketAddr) -> Option<&Session> {
        self.sessions.get(addr).map(|m| &m.session)
    }

    /// Get a mutable session by address
    pub fn get_session_mut(&mut self, addr: &SocketAddr) -> Option<&mut Session> {
        self.sessions.get_mut(addr).map(|m| &mut m.session)
    }

    /// Get a managed session by address
    pub fn get_managed(&self, addr: &SocketAddr) -> Option<&ManagedSession> {
        self.sessions.get(addr)
    }

    /// Get a mutable managed session by address
    pub fn get_managed_mut(&mut self, addr: &SocketAddr) -> Option<&mut ManagedSession> {
        self.sessions.get_mut(addr)
    }

    /// Remove a session
    pub fn remove_session(&mut self, addr: &SocketAddr) -> Option<Session> {
        self.sessions.remove(addr).map(|m| m.session)
    }

    /// Check if a session exists
    pub fn has_session(&self, addr: &SocketAddr) -> bool {
        self.sessions.contains_key(addr)
    }

    /// Get number of active sessions
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get total sessions created
    pub fn total_created(&self) -> u64 {
        self.total_created
    }

    /// Get session timeout
    pub fn session_timeout(&self) -> Duration {
        self.session_timeout
    }

    /// Set session timeout
    pub fn set_session_timeout(&mut self, timeout: Duration) {
        self.session_timeout = timeout;
    }

    /// Cleanup expired sessions
    pub fn cleanup_expired(&mut self) -> usize {
        let timeout = self.session_timeout;
        let before = self.sessions.len();

        self.sessions.retain(|_, session| !session.is_expired(timeout));

        before - self.sessions.len()
    }

    /// Get all session addresses
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.sessions.keys().copied().collect()
    }

    /// Get statistics for all sessions
    pub fn all_stats(&self) -> Vec<ManagedSessionStats> {
        self.sessions.values().map(|s| s.stats()).collect()
    }

    /// Iterate over all sessions
    pub fn iter(&self) -> impl Iterator<Item = (&SocketAddr, &ManagedSession)> {
        self.sessions.iter()
    }

    /// Iterate mutably over all sessions
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&SocketAddr, &mut ManagedSession)> {
        self.sessions.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::SessionId;

    fn create_test_session() -> Session {
        let id = SessionId::generate();
        let shared_secret = [42u8; 32];
        Session::from_shared_secret(id, &shared_secret, false)
    }

    #[test]
    fn test_session_manager_creation() {
        let manager = SessionManager::new(100);
        assert_eq!(manager.active_count(), 0);
        assert_eq!(manager.total_created(), 0);
    }

    #[test]
    fn test_add_session() {
        let mut manager = SessionManager::new(100);
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let session = create_test_session();

        assert!(manager.add_session(addr, session));
        assert_eq!(manager.active_count(), 1);
        assert_eq!(manager.total_created(), 1);
        assert!(manager.has_session(&addr));
    }

    #[test]
    fn test_get_session() {
        let mut manager = SessionManager::new(100);
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let session = create_test_session();
        let session_id = session.id();

        manager.add_session(addr, session);

        let retrieved = manager.get_session(&addr).unwrap();
        assert_eq!(retrieved.id(), session_id);
    }

    #[test]
    fn test_remove_session() {
        let mut manager = SessionManager::new(100);
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        manager.add_session(addr, create_test_session());
        assert_eq!(manager.active_count(), 1);

        manager.remove_session(&addr);
        assert_eq!(manager.active_count(), 0);
        assert!(!manager.has_session(&addr));
    }

    #[test]
    fn test_session_limit() {
        let mut manager = SessionManager::new(2);

        let addr1: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let addr3: SocketAddr = "127.0.0.1:3".parse().unwrap();

        assert!(manager.add_session(addr1, create_test_session()));
        assert!(manager.add_session(addr2, create_test_session()));
        assert!(!manager.add_session(addr3, create_test_session())); // Should fail

        assert_eq!(manager.active_count(), 2);
    }

    #[test]
    fn test_managed_session() {
        let session = create_test_session();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut managed = ManagedSession::new(session, addr, 1_000_000);

        assert_eq!(managed.remote_addr, addr);
        assert!(managed.age() >= Duration::ZERO);

        managed.touch();
        assert!(managed.idle_time() < Duration::from_secs(1));
    }

    #[test]
    fn test_session_expiry() {
        let session = create_test_session();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let managed = ManagedSession::new(session, addr, 1_000_000);

        // Not expired immediately
        assert!(!managed.is_expired(Duration::from_secs(120)));

        // Would be expired with 0 timeout
        assert!(managed.is_expired(Duration::ZERO));
    }

    #[test]
    fn test_all_stats() {
        let mut manager = SessionManager::new(100);

        let addr1: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:2".parse().unwrap();

        manager.add_session(addr1, create_test_session());
        manager.add_session(addr2, create_test_session());

        let stats = manager.all_stats();
        assert_eq!(stats.len(), 2);
    }
}
