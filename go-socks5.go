package main

import (
	"embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web
var webFiles embed.FS

// 常量定义
const (
	Version = 0x05

	// 认证方法
	MethodNoAuth       = 0x00
	MethodGSSAPI       = 0x01
	MethodUserPass     = 0x02
	MethodNoAcceptable = 0xFF

	// 命令类型
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	// 地址类型
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04

	// 响应状态
	RepSuccess                 = 0x00
	RepGeneralFailure          = 0x01
	RepConnectionNotAllowed    = 0x02
	RepNetworkUnreachable      = 0x03
	RepHostUnreachable         = 0x04
	RepConnectionRefused       = 0x05
	RepTTLExpired              = 0x06
	RepCommandNotSupported     = 0x07
	RepAddressTypeNotSupported = 0x08

	// 缓冲区大小
	BufferSize = 32 * 1024 // 优化：使用32KB缓冲区，减少内存占用

	// 超时配置
	DefaultConnectTimeout = 30 * time.Second
	DefaultReadTimeout     = 5 * time.Minute
	DefaultWriteTimeout    = 5 * time.Minute
	DefaultIdleTimeout     = 10 * time.Minute
)

// User 用户结构体
type User struct {
	Username string
	Password string
}

// UserManager 用户管理器
type UserManager struct {
	users map[string]*User
	mu    sync.RWMutex
}

func NewUserManager() *UserManager {
	return &UserManager{
		users: make(map[string]*User),
	}
}

func (um *UserManager) AddUser(user *User) {
	um.mu.Lock()
	defer um.mu.Unlock()
	um.users[user.Username] = user
}

func (um *UserManager) RemoveUser(username string) {
	um.mu.Lock()
	defer um.mu.Unlock()
	delete(um.users, username)
}

func (um *UserManager) Check(username, password string) bool {
	um.mu.RLock()
	defer um.mu.RUnlock()
	
	if user, exists := um.users[username]; exists {
		return user.Password == password
	}
	return false
}

func (um *UserManager) GetUser(username string) *User {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.users[username]
}

func (um *UserManager) GetUserCount() int {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return len(um.users)
}

// Config 配置文件结构
type Config struct {
	Port       int              `json:"port"`
	Auth       bool             `json:"auth"`
	Users      []User           `json:"users"`
	Allowed    []string         `json:"allowed"`
	WebPort   int              `json:"web_port"`   // Web界面端口
	RateLimits map[string]int64 `json:"rate_limits"` // 用户限速，单位：bytes/s
}

// TrafficStats 流量统计
type TrafficStats struct {
	UploadBytes   int64     // 上行字节数
	DownloadBytes int64     // 下行字节数
	UploadRate    float64   // 上行速率 bytes/s
	DownloadRate  float64   // 下行速率 bytes/s
	LastUpdate    time.Time // 最后更新时间
	Targets       []string  // 访问的目标地址列表
	mu            sync.RWMutex
}

// Session 会话结构体
type Session struct {
	ID           uint64
	ClientConn   net.Conn
	RemoteConn   net.Conn
	ClientAddr   string
	Username     string       // 登录用户名
	StartTime    time.Time
	Traffic      *TrafficStats // 流量统计
	targetAddr   string        // 当前连接的目标地址
	mu           sync.RWMutex
	attrs        map[string]interface{}
}

func NewSession(id uint64, conn net.Conn) *Session {
	return &Session{
		ID:         id,
		ClientConn: conn,
		ClientAddr: conn.RemoteAddr().String(),
		StartTime:  time.Now(),
		Traffic: &TrafficStats{
			LastUpdate: time.Now(),
			Targets:    make([]string, 0),
		},
		attrs: make(map[string]interface{}),
	}
}

func (s *Session) AddTarget(target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targetAddr = target
	if s.Traffic != nil {
		s.Traffic.mu.Lock()
		// 检查是否已存在
		exists := false
		for _, t := range s.Traffic.Targets {
			if t == target {
				exists = true
				break
			}
		}
		if !exists {
			s.Traffic.Targets = append(s.Traffic.Targets, target)
		}
		s.Traffic.mu.Unlock()
	}
}

func (s *Session) GetTarget() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.targetAddr
}

func (s *Session) AddUpload(bytes int64) {
	if s.Traffic != nil {
		now := time.Now()
		s.Traffic.mu.Lock()
		s.Traffic.UploadBytes += bytes
		// 计算速率
		if !s.Traffic.LastUpdate.IsZero() {
			elapsed := now.Sub(s.Traffic.LastUpdate).Seconds()
			if elapsed > 0 {
				s.Traffic.UploadRate = float64(bytes) / elapsed
			}
		}
		s.Traffic.LastUpdate = now
		s.Traffic.mu.Unlock()
	}
}

func (s *Session) AddDownload(bytes int64) {
	if s.Traffic != nil {
		now := time.Now()
		s.Traffic.mu.Lock()
		s.Traffic.DownloadBytes += bytes
		// 计算速率
		if !s.Traffic.LastUpdate.IsZero() {
			elapsed := now.Sub(s.Traffic.LastUpdate).Seconds()
			if elapsed > 0 {
				s.Traffic.DownloadRate = float64(bytes) / elapsed
			}
		}
		s.Traffic.LastUpdate = now
		s.Traffic.mu.Unlock()
	}
}

func (s *Session) SetAttr(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attrs[key] = value
}

func (s *Session) GetAttr(key string) interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.attrs[key]
}

func (s *Session) Close() {
	if s.ClientConn != nil {
		s.ClientConn.Close()
	}
	if s.RemoteConn != nil {
		s.RemoteConn.Close()
	}
}

func (s *Session) GetUsername() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Username
}

func (s *Session) SetUsername(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Username = username
}

// RateLimiter 限速器（令牌桶算法）
type RateLimiter struct {
	rate     int64 // 速率 bytes/s
	capacity int64 // 桶容量
	tokens   int64 // 当前令牌数
	lastTime time.Time
	mu       sync.Mutex
}

func NewRateLimiter(rate int64) *RateLimiter {
	if rate <= 0 {
		return nil // 无限制
	}
	return &RateLimiter{
		rate:     rate,
		capacity: rate * 2, // 桶容量为速率的2倍
		tokens:   rate * 2,
		lastTime: time.Now(),
	}
}

func (rl *RateLimiter) Allow(bytes int64) bool {
	if rl == nil {
		return true // 无限制
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.lastTime = now
	
	// 添加令牌
	if elapsed > 0 {
		newTokens := int64(float64(rl.rate) * elapsed)
		rl.tokens += newTokens
		if rl.tokens > rl.capacity {
			rl.tokens = rl.capacity
		}
	}
	
	// 检查是否有足够的令牌
	if rl.tokens >= bytes {
		rl.tokens -= bytes
		return true
	}
	return false
}

func (rl *RateLimiter) Wait(bytes int64) {
	if rl == nil {
		return
	}
	for !rl.Allow(bytes) {
		time.Sleep(10 * time.Millisecond)
	}
}

// SocketPipe 套接字管道，用于双向数据传输
type SocketPipe struct {
	conn1       net.Conn
	conn2       net.Conn
	running     bool
	mu          sync.RWMutex
	done        chan struct{} // 用于通知传输完成
	wg          sync.WaitGroup // 等待所有传输完成
	session     *Session       // 关联的会话，用于流量统计
	uploadLimiter  *RateLimiter // 上行限速
	downloadLimiter *RateLimiter // 下行限速
}

func NewSocketPipe(conn1, conn2 net.Conn, session *Session, uploadRate, downloadRate int64) *SocketPipe {
	return &SocketPipe{
		conn1:          conn1,
		conn2:          conn2,
		done:           make(chan struct{}),
		session:        session,
		uploadLimiter:  NewRateLimiter(uploadRate),
		downloadLimiter: NewRateLimiter(downloadRate),
	}
}

func (sp *SocketPipe) Start() {
	sp.mu.Lock()
	if sp.running {
		sp.mu.Unlock()
		return
	}
	sp.running = true
	sp.mu.Unlock()

	sp.wg.Add(2)
	// conn1是客户端连接，conn2是远程连接
	// 客户端->远程：上行
	// 远程->客户端：下行
	go sp.transfer(sp.conn1, sp.conn2, true)
	go sp.transfer(sp.conn2, sp.conn1, false)

	// 等待任一方向传输完成，然后停止
	go func() {
		sp.wg.Wait()
		close(sp.done)
		sp.Stop()
	}()
}

func (sp *SocketPipe) Stop() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	
	if !sp.running {
		return
	}
	
	sp.running = false
	if sp.conn1 != nil {
		sp.conn1.Close()
	}
	if sp.conn2 != nil {
		sp.conn2.Close()
	}
}

func (sp *SocketPipe) IsRunning() bool {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	return sp.running
}

func (sp *SocketPipe) Wait() {
	<-sp.done
}

func (sp *SocketPipe) transfer(src, dst net.Conn, isClientToRemote bool) {
	defer sp.wg.Done()
	buffer := make([]byte, BufferSize)
	
	// 设置连接的keep-alive和初始超时
	if tcpConn, ok := src.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	if tcpConn, ok := dst.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	
	var limiter *RateLimiter
	if isClientToRemote {
		limiter = sp.uploadLimiter // 客户端->服务器，上行
	} else {
		limiter = sp.downloadLimiter // 服务器->客户端，下行
	}
	
	for {
		sp.mu.RLock()
		running := sp.running
		sp.mu.RUnlock()
		
		if !running {
			break
		}
		
		// 设置读取超时（每次循环更新，避免长时间阻塞）
		if tcpConn, ok := src.(*net.TCPConn); ok {
			tcpConn.SetReadDeadline(time.Now().Add(DefaultReadTimeout))
		}
		
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") && !strings.Contains(err.Error(), "i/o timeout") {
				log.Printf("Read error: %v", err)
			}
			break
		}
		
		if n > 0 {
			// 限速
			if limiter != nil {
				limiter.Wait(int64(n))
			}
			
			// 流量统计
			if sp.session != nil {
				if isClientToRemote {
					sp.session.AddUpload(int64(n))
				} else {
					sp.session.AddDownload(int64(n))
				}
			}
			
			// 设置写入超时
			if tcpConn, ok := dst.(*net.TCPConn); ok {
				tcpConn.SetWriteDeadline(time.Now().Add(DefaultWriteTimeout))
			}
			
			_, err = dst.Write(buffer[:n])
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") && !strings.Contains(err.Error(), "i/o timeout") {
					log.Printf("Write error: %v", err)
				}
				break
			}
		}
	}
}

// SOCKS5Server SOCKS5服务器
type SOCKS5Server struct {
	port          int
	auth          bool
	userManager   *UserManager
	allowedIPs    map[string]bool
	listener      net.Listener
	sessions      map[uint64]*Session
	sessionID     uint64
	mu            sync.RWMutex
	running       bool
	maxSessions   int // 最大连接数限制
	currentConns  int // 当前连接数
	connSemaphore chan struct{} // 连接数信号量
	webPort       int // Web界面端口
	rateLimits    map[string]int64 // 用户限速配置
	webServer     *http.Server // Web服务器
	blockedUsers  map[string]bool // 被阻断的用户列表
	blockMu       sync.RWMutex // 阻断列表的锁
}

func NewSOCKS5Server(port int, auth bool, userManager *UserManager, allowedIPs []string, webPort int, rateLimits map[string]int64) *SOCKS5Server {
	allowedMap := make(map[string]bool)
	for _, ip := range allowedIPs {
		allowedMap[ip] = true
	}
	
	maxSessions := 1000 // 默认最大1000个并发连接
	connSemaphore := make(chan struct{}, maxSessions)
	
	return &SOCKS5Server{
		port:          port,
		auth:          auth,
		userManager:   userManager,
		allowedIPs:    allowedMap,
		sessions:      make(map[uint64]*Session),
		maxSessions:   maxSessions,
		connSemaphore: connSemaphore,
		webPort:       webPort,
		rateLimits:    rateLimits,
		blockedUsers:  make(map[string]bool),
	}
}

func (s *SOCKS5Server) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", s.port, err)
	}
	
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
	
	log.Printf("SOCKS5 server started on port %d", s.port)
	
	// 启动Web服务器
	if s.webPort > 0 {
		go s.startWebServer()
		log.Printf("Web dashboard started on port %d", s.webPort)
	}
	
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.RLock()
			running := s.running
			s.mu.RUnlock()
			
			if !running {
				break
			}
			log.Printf("Accept error: %v", err)
			continue
		}
		
		go s.handleConnection(conn)
	}
	
	return nil
}

func (s *SOCKS5Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}
	
	// 关闭Web服务器
	if s.webServer != nil {
		s.webServer.Close()
	}
	
	// 关闭所有会话
	for _, session := range s.sessions {
		session.Close()
	}
	s.sessions = make(map[uint64]*Session)
	
	log.Println("SOCKS5 server stopped")
}

// formatBytes 格式化字节数为可读格式
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// startWebServer 启动Web服务器
func (s *SOCKS5Server) startWebServer() {
	mux := http.NewServeMux()
	
	// API端点
	mux.HandleFunc("/api/stats", s.handleAPIStats)
	mux.HandleFunc("/api/users", s.handleAPIUsers)
	mux.HandleFunc("/api/sessions", s.handleAPISessions)
	mux.HandleFunc("/api/block", s.handleAPIBlock)
	mux.HandleFunc("/api/unblock", s.handleAPIUnblock)
	mux.HandleFunc("/api/blocked", s.handleAPIBlocked)
	
	// Web界面
	mux.HandleFunc("/", s.handleWebDashboard)
	
	s.webServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.webPort),
		Handler: mux,
	}
	
	if err := s.webServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("Web server error: %v", err)
	}
}

// handleAPIStats 处理统计API
func (s *SOCKS5Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	s.mu.RLock()
	sessions := make([]map[string]interface{}, 0)
	for _, session := range s.sessions {
		sessData := make(map[string]interface{})
		sessData["id"] = session.ID
		sessData["username"] = session.GetUsername()
		sessData["client_addr"] = session.ClientAddr
		sessData["start_time"] = session.StartTime.Format(time.RFC3339)
		sessData["duration"] = time.Since(session.StartTime).String()
		
		if session.Traffic != nil {
			session.Traffic.mu.RLock()
			sessData["upload_bytes"] = session.Traffic.UploadBytes
			sessData["download_bytes"] = session.Traffic.DownloadBytes
			sessData["upload_rate"] = session.Traffic.UploadRate
			sessData["download_rate"] = session.Traffic.DownloadRate
			sessData["targets"] = session.Traffic.Targets
			session.Traffic.mu.RUnlock()
		}
		sessions = append(sessions, sessData)
	}
	s.mu.RUnlock()
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_sessions": len(sessions),
		"sessions":       sessions,
	})
}

// handleAPIUsers 处理用户统计API
func (s *SOCKS5Server) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	s.mu.RLock()
	userStats := make(map[string]map[string]interface{})
	for _, session := range s.sessions {
		username := session.GetUsername()
		if username == "" {
			username = "anonymous"
		}
		
		if _, ok := userStats[username]; !ok {
			userStats[username] = map[string]interface{}{
				"username":        username,
				"active_sessions": 0,
				"total_upload":    int64(0),
				"total_download":  int64(0),
				"upload_rate":     0.0,
				"download_rate":   0.0,
				"targets":         make([]string, 0),
			}
		}
		
		stats := userStats[username]
		stats["active_sessions"] = stats["active_sessions"].(int) + 1
		
		if session.Traffic != nil {
			session.Traffic.mu.RLock()
			stats["total_upload"] = stats["total_upload"].(int64) + session.Traffic.UploadBytes
			stats["total_download"] = stats["total_download"].(int64) + session.Traffic.DownloadBytes
			stats["upload_rate"] = stats["upload_rate"].(float64) + session.Traffic.UploadRate
			stats["download_rate"] = stats["download_rate"].(float64) + session.Traffic.DownloadRate
			
			// 合并目标地址
			targetsMap := make(map[string]bool)
			for _, t := range stats["targets"].([]string) {
				targetsMap[t] = true
			}
			for _, t := range session.Traffic.Targets {
				targetsMap[t] = true
			}
			targets := make([]string, 0, len(targetsMap))
			for t := range targetsMap {
				targets = append(targets, t)
			}
			stats["targets"] = targets
			session.Traffic.mu.RUnlock()
		}
	}
	s.mu.RUnlock()
	
	users := make([]map[string]interface{}, 0, len(userStats))
	for _, stats := range userStats {
		users = append(users, stats)
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": users,
	})
}

// handleAPISessions 处理会话列表API
func (s *SOCKS5Server) handleAPISessions(w http.ResponseWriter, r *http.Request) {
	s.handleAPIStats(w, r)
}

// handleWebDashboard 处理Web Dashboard页面
func (s *SOCKS5Server) handleWebDashboard(w http.ResponseWriter, r *http.Request) {
	// 从嵌入的文件系统中读取HTML模板
	content, err := webFiles.ReadFile("web/dashboard.html")
	if err != nil {
		log.Printf("Failed to read dashboard.html: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	t, err := template.New("dashboard").Parse(string(content))
	if err != nil {
		log.Printf("Failed to parse dashboard template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	t.Execute(w, nil)
}

// handleAPIBlock 阻断用户API
func (s *SOCKS5Server) handleAPIBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "username parameter is required", http.StatusBadRequest)
		return
	}
	
	s.blockMu.Lock()
	s.blockedUsers[username] = true
	s.blockMu.Unlock()
	
	log.Printf("[BLOCK] User %s has been blocked", username)
	
	// 关闭该用户的所有会话
	s.mu.Lock()
	sessionsToClose := make([]*Session, 0)
	for _, session := range s.sessions {
		if session.GetUsername() == username {
			sessionsToClose = append(sessionsToClose, session)
		}
	}
	s.mu.Unlock()
	
	// 关闭所有相关会话
	for _, session := range sessionsToClose {
		log.Printf("[BLOCK] Closing session[%d] for blocked user %s", session.ID, username)
		session.Close()
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("User %s has been blocked", username),
		"closed_sessions": len(sessionsToClose),
	})
}

// handleAPIUnblock 解除阻断用户API
func (s *SOCKS5Server) handleAPIUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "username parameter is required", http.StatusBadRequest)
		return
	}
	
	s.blockMu.Lock()
	delete(s.blockedUsers, username)
	s.blockMu.Unlock()
	
	log.Printf("[BLOCK] User %s has been unblocked", username)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("User %s has been unblocked", username),
	})
}

// handleAPIBlocked 获取被阻断用户列表API
func (s *SOCKS5Server) handleAPIBlocked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	s.blockMu.RLock()
	blocked := make([]string, 0, len(s.blockedUsers))
	for username := range s.blockedUsers {
		blocked = append(blocked, username)
	}
	s.blockMu.RUnlock()
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"blocked_users": blocked,
	})
}

func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()
	clientIP, _, _ := net.SplitHostPort(clientAddr)
	
	// 连接数限制检查
	select {
	case s.connSemaphore <- struct{}{}:
		// 获取到连接槽位
		defer func() {
			<-s.connSemaphore // 释放连接槽位
		}()
	default:
		log.Printf("Connection from %s rejected: max connections reached", clientAddr)
		conn.Close()
		return
	}
	
	// IP白名单检查
	if len(s.allowedIPs) > 0 && !s.allowedIPs[clientIP] {
		log.Printf("Connection from %s rejected: IP not in allowed list", clientAddr)
		conn.Close()
		return
	}
	
	// 设置连接超时
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadDeadline(time.Now().Add(DefaultIdleTimeout))
	}
	
	s.mu.Lock()
	s.sessionID++
	session := NewSession(s.sessionID, conn)
	s.sessions[session.ID] = session
	s.currentConns++
	s.mu.Unlock()
	
	defer func() {
		duration := time.Since(session.StartTime)
		username := session.GetUsername()
		
		// 获取流量统计
		var uploadBytes, downloadBytes int64
		var targets []string
		if session.Traffic != nil {
			session.Traffic.mu.RLock()
			uploadBytes = session.Traffic.UploadBytes
			downloadBytes = session.Traffic.DownloadBytes
			targets = make([]string, len(session.Traffic.Targets))
			copy(targets, session.Traffic.Targets)
			session.Traffic.mu.RUnlock()
		}
		
		s.mu.Lock()
		delete(s.sessions, session.ID)
		s.currentConns--
		s.mu.Unlock()
		session.Close()
		
		// 增强的审计日志
		if username != "" {
			log.Printf("[AUDIT] Session[%d] user %s from %s closed (duration: %v, upload: %s, download: %s, targets: %v)", 
				session.ID, username, clientAddr, duration,
				formatBytes(uploadBytes), formatBytes(downloadBytes), targets)
			log.Printf("[SESSION] Session[%d] closed from %s (user: %s, duration: %v)", session.ID, clientAddr, username, duration)
		} else {
			log.Printf("[AUDIT] Session[%d] from %s closed (duration: %v, upload: %s, download: %s, targets: %v)", 
				session.ID, clientAddr, duration,
				formatBytes(uploadBytes), formatBytes(downloadBytes), targets)
			log.Printf("[SESSION] Session[%d] closed from %s (duration: %v)", session.ID, clientAddr, duration)
		}
	}()
	
	log.Printf("[SESSION] Session[%d] started from %s", session.ID, clientAddr)
	
	// 协商认证方法
	if err := s.negotiateAuth(session); err != nil {
		log.Printf("Session[%d] auth negotiation failed: %v", session.ID, err)
		return
	}
	
	// 处理请求
	if err := s.handleRequest(session); err != nil {
		log.Printf("Session[%d] request handling failed: %v", session.ID, err)
		return
	}
}

func (s *SOCKS5Server) negotiateAuth(session *Session) error {
	conn := session.ClientConn
	
	// 设置读取超时
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	
	// 读取版本和方法数量
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	
	if buf[0] != Version {
		return errors.New("unsupported SOCKS version")
	}
	
	// 读取方法列表
	nmethods := int(buf[1])
	if nmethods == 0 || nmethods > 255 {
		return errors.New("invalid number of methods")
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	
	// 选择认证方法
	selectedMethod := MethodNoAcceptable
	if !s.auth {
		// 不需要认证，检查是否支持无认证
		for _, method := range methods {
			if method == MethodNoAuth {
				selectedMethod = MethodNoAuth
				break
			}
		}
	} else {
		// 需要认证，检查是否支持用户名密码认证
		for _, method := range methods {
			if method == MethodUserPass {
				selectedMethod = MethodUserPass
				break
			}
		}
	}
	
	// 发送选择的认证方法
	response := []byte{Version, byte(selectedMethod)}
	if _, err := conn.Write(response); err != nil {
		return err
	}
	
	if selectedMethod == MethodNoAcceptable {
		return errors.New("no acceptable authentication method")
	}
	
	// 如果需要用户名密码认证
	if selectedMethod == MethodUserPass {
		if err := s.handleUserAuth(session); err != nil {
			return err
		}
		
		// 检查用户是否被阻断
		username := session.GetUsername()
		if username != "" {
			s.blockMu.RLock()
			isBlocked := s.blockedUsers[username]
			s.blockMu.RUnlock()
			
			if isBlocked {
				log.Printf("[BLOCK] Session[%d] user %s from %s rejected: user is blocked", session.ID, username, session.ClientAddr)
				conn := session.ClientConn
				conn.Close()
				// 从会话列表中移除
				s.mu.Lock()
				delete(s.sessions, session.ID)
				s.currentConns--
				s.mu.Unlock()
				return errors.New("user is blocked")
			}
		}
	}
	
	return nil
}

func (s *SOCKS5Server) handleUserAuth(session *Session) error {
	conn := session.ClientConn
	clientAddr := session.ClientAddr
	
	// 读取认证版本
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	
	if buf[0] != 0x01 { // 用户名密码认证子协商版本
		return errors.New("unsupported auth version")
	}
	
	// 读取用户名长度和用户名
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	ulen := int(buf[0])
	if ulen == 0 || ulen > 255 {
		log.Printf("[AUTH] Session[%d] from %s: invalid username length", session.ID, clientAddr)
		return errors.New("invalid username length")
	}
	username := make([]byte, ulen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	usernameStr := string(username)
	
	// 读取密码长度和密码
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	plen := int(buf[0])
	if plen == 0 || plen > 255 {
		log.Printf("[AUTH] Session[%d] from %s: invalid password length (username: %s)", session.ID, clientAddr, usernameStr)
		return errors.New("invalid password length")
	}
	password := make([]byte, plen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	
	// 验证用户名密码
	if s.userManager.Check(usernameStr, string(password)) {
		// 认证成功
		session.SetUsername(usernameStr)
		response := []byte{0x01, 0x00}
		_, err := conn.Write(response)
		if err != nil {
			log.Printf("[AUTH] Session[%d] from %s: login success but failed to send response (username: %s)", session.ID, clientAddr, usernameStr)
			return err
		}
		log.Printf("[AUTH] Session[%d] from %s: login SUCCESS (username: %s)", session.ID, clientAddr, usernameStr)
		return nil
	} else {
		// 认证失败
		response := []byte{0x01, 0x01}
		conn.Write(response)
		log.Printf("[AUTH] Session[%d] from %s: login FAILED (username: %s, reason: invalid credentials)", session.ID, clientAddr, usernameStr)
		return errors.New("authentication failed")
	}
}

func (s *SOCKS5Server) handleRequest(session *Session) error {
	conn := session.ClientConn
	
	// 设置读取超时
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	
	// 读取请求头
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	
	if header[0] != Version {
		return errors.New("unsupported SOCKS version")
	}
	
	command := header[1]
	// header[2] is RSV, reserved
	addrType := header[3]
	
	var host string
	var port int
	
	// 解析目标地址
	switch addrType {
	case AddrTypeIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	case AddrTypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		domainLen := int(lenBuf[0])
		if domainLen == 0 || domainLen > 255 {
			s.sendReply(session, RepAddressTypeNotSupported, nil, 0)
			return errors.New("invalid domain length")
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return err
		}
		host = string(domain)
	case AddrTypeIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	default:
		s.sendReply(session, RepAddressTypeNotSupported, nil, 0)
		return errors.New("unsupported address type")
	}
	
	// 读取端口
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return err
	}
	port = int(binary.BigEndian.Uint16(portBuf))
	
	// 处理命令
	switch command {
	case CmdConnect:
		return s.handleConnect(session, host, port)
	case CmdBind:
		return s.handleBind(session)
	case CmdUDPAssociate:
		return s.handleUDPAssociate(session)
	default:
		s.sendReply(session, RepCommandNotSupported, nil, 0)
		return fmt.Errorf("unsupported command: %d", command)
	}
}

func (s *SOCKS5Server) getRateLimit(username string) (int64, int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.rateLimits != nil {
		if rate, ok := s.rateLimits[username]; ok {
			return rate, rate // 上下行使用相同速率
		}
	}
	return 0, 0 // 无限制
}

func (s *SOCKS5Server) handleConnect(session *Session, host string, port int) error {
	username := session.GetUsername()
	clientAddr := session.ClientAddr
	
	// 再次检查用户是否被阻断（防止在连接过程中被阻断）
	if username != "" {
		s.blockMu.RLock()
		isBlocked := s.blockedUsers[username]
		s.blockMu.RUnlock()
		
		if isBlocked {
			log.Printf("[BLOCK] Session[%d] user %s from %s connecting to %s:%d rejected: user is blocked", 
				session.ID, username, clientAddr, host, port)
			s.sendReply(session, RepConnectionNotAllowed, nil, 0)
			return errors.New("user is blocked")
		}
	}
	
	targetAddr := fmt.Sprintf("%s:%d", host, port)
	
	// 记录目标地址
	session.AddTarget(targetAddr)
	
	// 增强日志记录（审计）
	if username != "" {
		log.Printf("[AUDIT] Session[%d] user %s from %s connecting to %s:%d", session.ID, username, clientAddr, host, port)
		log.Printf("[CONNECT] Session[%d] user %s from %s connecting to %s:%d", session.ID, username, clientAddr, host, port)
	} else {
		log.Printf("[AUDIT] Session[%d] from %s connecting to %s:%d", session.ID, clientAddr, host, port)
		log.Printf("[CONNECT] Session[%d] from %s connecting to %s:%d", session.ID, clientAddr, host, port)
	}
	
	// 连接目标服务器（带超时）
	connectAddr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout: DefaultConnectTimeout,
	}
	remoteConn, err := dialer.Dial("tcp", connectAddr)
	if err != nil {
		var replyCode byte
		switch {
		case strings.Contains(err.Error(), "connection refused"):
			replyCode = RepConnectionRefused
		case strings.Contains(err.Error(), "network is unreachable"):
			replyCode = RepNetworkUnreachable
		case strings.Contains(err.Error(), "no route to host"):
			replyCode = RepHostUnreachable
		case strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "timeout"):
			replyCode = RepTTLExpired
		default:
			replyCode = RepGeneralFailure
		}
		s.sendReply(session, replyCode, nil, 0)
		if username != "" {
			log.Printf("[CONNECT] Session[%d] user %s from %s failed to connect to %s:%d: %v", session.ID, username, clientAddr, host, port, err)
		} else {
			log.Printf("[CONNECT] Session[%d] from %s failed to connect to %s:%d: %v", session.ID, clientAddr, host, port, err)
		}
		return fmt.Errorf("failed to connect to target: %v", err)
	}
	
	// 设置远程连接的 keep-alive
	if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	
	session.RemoteConn = remoteConn
	
	// 获取远程连接的本地地址
	localAddr := remoteConn.LocalAddr().(*net.TCPAddr)
	
	// 发送成功响应
	if err := s.sendReply(session, RepSuccess, localAddr.IP, localAddr.Port); err != nil {
		remoteConn.Close()
		return err
	}
	
	if username != "" {
		log.Printf("[AUDIT] Session[%d] user %s from %s successfully connected to %s:%d", session.ID, username, clientAddr, host, port)
		log.Printf("[CONNECT] Session[%d] user %s from %s successfully connected to %s:%d", session.ID, username, clientAddr, host, port)
	} else {
		log.Printf("[AUDIT] Session[%d] from %s successfully connected to %s:%d", session.ID, clientAddr, host, port)
		log.Printf("[CONNECT] Session[%d] from %s successfully connected to %s:%d", session.ID, clientAddr, host, port)
	}
	
	// 获取限速配置
	uploadRate, downloadRate := s.getRateLimit(username)
	
	// 开始数据传输（带限速和流量统计）
	pipe := NewSocketPipe(session.ClientConn, remoteConn, session, uploadRate, downloadRate)
	pipe.Start()
	
	// 等待传输完成（使用 Wait 而不是轮询）
	pipe.Wait()
	
	// 连接关闭日志（审计）
	if username != "" {
		session.Traffic.mu.RLock()
		uploadBytes := session.Traffic.UploadBytes
		downloadBytes := session.Traffic.DownloadBytes
		session.Traffic.mu.RUnlock()
		log.Printf("[AUDIT] Session[%d] user %s from %s disconnected from %s:%d (upload: %s, download: %s)", 
			session.ID, username, clientAddr, host, port, 
			formatBytes(uploadBytes), formatBytes(downloadBytes))
	}
	
	return nil
}

func (s *SOCKS5Server) handleBind(session *Session) error {
	// BIND命令暂不支持
	s.sendReply(session, RepCommandNotSupported, nil, 0)
	return errors.New("BIND command not supported")
}

func (s *SOCKS5Server) handleUDPAssociate(session *Session) error {
	// UDP ASSOCIATE命令暂不支持
	s.sendReply(session, RepCommandNotSupported, nil, 0)
	return errors.New("UDP ASSOCIATE command not supported")
}

func (s *SOCKS5Server) sendReply(session *Session, rep byte, bindIP net.IP, bindPort int) error {
	conn := session.ClientConn
	
	response := make([]byte, 4)
	response[0] = Version
	response[1] = rep
	response[2] = 0x00 // RSV
	
	var addr []byte
	if bindIP == nil {
		// 使用0.0.0.0:0表示绑定地址不可用
		response[3] = AddrTypeIPv4
		addr = make([]byte, 6) // 4 bytes IP + 2 bytes port
	} else {
		if bindIP.To4() != nil {
			response[3] = AddrTypeIPv4
			addr = make([]byte, 6)
			copy(addr, bindIP.To4())
		} else {
			response[3] = AddrTypeIPv6
			addr = make([]byte, 18)
			copy(addr, bindIP.To16())
		}
		binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(bindPort))
	}
	
	// 设置写入超时
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}
	
	// 合并响应头和地址信息，一次性写入（减少系统调用）
	fullResponse := append(response, addr...)
	if _, err := conn.Write(fullResponse); err != nil {
		return err
	}
	
	return nil
}

// 守护进程相关函数
func writePIDFile(pidFile string) error {
	pid := os.Getpid()
	return os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0644)
}

func readPIDFile(pidFile string) (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func stopServer(pidFile string) {
	fmt.Print("Stopping server... ")
	
	pid, err := readPIDFile(pidFile)
	if err != nil {
		fmt.Println("server is not running")
		return
	}
	
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Println("server is not running")
		os.Remove(pidFile)
		return
	}
	
	// 发送SIGTERM信号
	if err := process.Signal(syscall.SIGTERM); err != nil {
		fmt.Println("failed to stop server")
		return
	}
	
	// 等待进程退出
	time.Sleep(2 * time.Second)
	
	// 检查进程是否还在运行
	if err := process.Signal(syscall.Signal(0)); err != nil {
		os.Remove(pidFile)
		fmt.Println("[OK]")
	} else {
		fmt.Println("failed to stop server")
	}
}

func statusServer(pidFile string) {
	pid, err := readPIDFile(pidFile)
	if err != nil {
		fmt.Println("server is stopped")
		return
	}
	
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Println("server is stopped")
		return
	}
	
	// 检查进程是否在运行
	if err := process.Signal(syscall.Signal(0)); err != nil {
		fmt.Println("server is stopped")
		os.Remove(pidFile)
	} else {
		fmt.Printf("server (pid %d) is running...\n", pid)
	}
}

func showHelp() {
	fmt.Println("Usage: gosocks5 <command> [options]")
	fmt.Println("Commands:")
	fmt.Println("  start     Start the SOCKS5 server")
	fmt.Println("  stop      Stop the SOCKS5 server")
	fmt.Println("  restart   Restart the SOCKS5 server")
	fmt.Println("  status    Show server status")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  --port=<port>          Server port (default: 1080)")
	fmt.Println("  --config=<file>        Configuration file path (JSON format)")
	fmt.Println("                         If config file is provided, auth and users will be loaded from it")
	fmt.Println("  --auth=<users>         Enable authentication with username:password pairs")
	fmt.Println("                         Example: --auth=user1:pass1,user2:pass2")
	fmt.Println("                         Note: This option is ignored if --config is used")
	fmt.Println("  --allowed=<ips>        Comma-separated list of allowed client IPs")
	fmt.Println("  --log=<true|false>     Enable logging (default: true)")
	fmt.Println("  --pidfile=<file>       PID file path (default: /tmp/gosocks5.pid)")
}

func main() {
	if len(os.Args) < 2 {
		showHelp()
		return
	}
	
	command := os.Args[1]
	
	// 定义命令行标志
	portFlag := flag.Int("port", 1080, "Server port")
	configFlag := flag.String("config", "", "Configuration file path")
	authFlag := flag.String("auth", "", "Authentication users")
	allowedFlag := flag.String("allowed", "", "Allowed IPs")
	logFlag := flag.Bool("log", true, "Enable logging")
	pidFileFlag := flag.String("pidfile", "/tmp/gosocks5.pid", "PID file path")
	
	// 重新解析标志，跳过命令参数
	flag.CommandLine.Parse(os.Args[2:])
	
	switch command {
	case "start":
		startServer(*portFlag, *configFlag, *authFlag, *allowedFlag, *logFlag, *pidFileFlag)
	case "stop":
		stopServer(*pidFileFlag)
	case "restart":
		stopServer(*pidFileFlag)
		time.Sleep(1 * time.Second)
		startServer(*portFlag, *configFlag, *authFlag, *allowedFlag, *logFlag, *pidFileFlag)
	case "status":
		statusServer(*pidFileFlag)
	default:
		showHelp()
	}
}

// loadConfig 从配置文件加载配置
func loadConfig(configPath string) (*Config, error) {
	if configPath == "" {
		return nil, nil
	}
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	
	return &config, nil
}

func startServer(port int, configPath, authStr, allowedStr string, enableLog bool, pidFile string) {
	// 设置日志
	if !enableLog {
		log.SetOutput(io.Discard)
	} else {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	
	// 创建用户管理器
	userManager := NewUserManager()
	authEnabled := false
	var allowedIPs []string
	var webPort int
	var rateLimits map[string]int64
	
	// 优先从配置文件加载
	if configPath != "" {
		config, err := loadConfig(configPath)
		if err != nil {
			log.Printf("Failed to load config file: %v", err)
			log.Println("Falling back to command line arguments")
		} else {
			log.Printf("Configuration loaded from %s", configPath)
			
			// 使用配置文件中的端口（如果提供了）
			if config.Port > 0 {
				port = config.Port
			}
			
			// 从配置文件加载Web端口
			if config.WebPort > 0 {
				webPort = config.WebPort
			}
			
			// 从配置文件加载认证信息
			if config.Auth && len(config.Users) > 0 {
				authEnabled = true
				for _, user := range config.Users {
					userManager.AddUser(&User{
						Username: user.Username,
						Password: user.Password,
					})
					log.Printf("Loaded user from config: %s", user.Username)
				}
			}
			
			// 从配置文件加载 IP 白名单
			if len(config.Allowed) > 0 {
				allowedIPs = config.Allowed
			}
			
			// 从配置文件加载限速配置
			if config.RateLimits != nil {
				rateLimits = config.RateLimits
				log.Printf("Loaded rate limits for %d user(s)", len(rateLimits))
			}
		}
	}
	
	// 如果配置文件没有提供认证信息，则使用命令行参数（向后兼容）
	if !authEnabled && authStr != "" {
		authEnabled = true
		users := strings.Split(authStr, ",")
		for _, user := range users {
			parts := strings.Split(user, ":")
			if len(parts) == 2 {
				userManager.AddUser(&User{
					Username: parts[0],
					Password: parts[1],
				})
				log.Printf("Added user from command line: %s", parts[0])
			}
		}
	}
	
	// 如果配置文件没有提供 IP 白名单，则使用命令行参数
	if len(allowedIPs) == 0 && allowedStr != "" {
		allowedIPs = strings.Split(allowedStr, ",")
	}
	
	if authEnabled {
		log.Printf("Authentication enabled with %d user(s)", userManager.GetUserCount())
	} else {
		log.Println("Authentication disabled")
	}
	
	// 创建服务器
	server := NewSOCKS5Server(port, authEnabled, userManager, allowedIPs, webPort, rateLimits)
	
	// 写入PID文件
	if err := writePIDFile(pidFile); err != nil {
		log.Printf("Failed to write PID file: %v", err)
		return
	}
	
	// 设置信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		<-sigCh
		log.Println("Received shutdown signal")
		server.Stop()
		os.Remove(pidFile)
		os.Exit(0)
	}()
	
	// 启动服务器
	log.Printf("Starting SOCKS5 server on port %d", port)
	if err := server.Start(); err != nil {
		log.Printf("Server error: %v", err)
		os.Remove(pidFile)
		os.Exit(1)
	}
}
