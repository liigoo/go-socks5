# go-socks5

一个用 Go 语言实现的高性能 SOCKS5 代理服务器，支持用户认证、连接数限制、实时流量监控等特性。

## 特性

- ✅ **完整 SOCKS5 协议支持**：支持 CONNECT 命令（TCP 代理）
- ✅ **用户认证**：支持用户名/密码认证（RFC 1929）
  - 支持从配置文件或命令行参数加载用户
  - 详细的登录日志记录
- ✅ **配置文件支持**：支持 JSON 格式的配置文件
- ✅ **日志记录**：详细的用户登录和使用日志
- ✅ **连接管理**：
  - 最大并发连接数限制（默认 1000）
  - 连接超时控制
  - TCP Keep-Alive 支持
- ✅ **高性能优化**：
  - 高效的双向数据传输
  - 优化的缓冲区管理（32KB）
  - 异步连接处理
- ✅ **安全性**：
  - 输入验证和长度检查
  - 超时保护机制
  - 优雅关闭
- ✅ **守护进程支持**：
  - PID 文件管理
  - 信号处理（SIGINT/SIGTERM）
  - 服务状态查询
- ✅ **Web监控面板**：
  - 实时流量监控图表
  - 用户和会话统计
  - IP地址筛选功能
  - 用户阻断/解除阻断功能
- ✅ **流量统计**：
  - 实时上传/下载速率监控
  - 总流量统计
  - 目标地址跟踪
- ✅ **用户限速**：支持按用户设置上传/下载速率限制
- ✅ **用户阻断**：支持动态阻断/解除阻断用户

## 系统要求

- Go 1.16 或更高版本（用于编译）
- Linux/Windows/macOS 操作系统

## 安装

### 编译安装

```bash
# 克隆或下载项目
cd go-socks5

# 编译
go build -o gosocks5 go-socks5.go

# Windows 下编译
go build -o gosocks5.exe go-socks5.go
```

### 直接使用二进制文件

如果你有预编译的二进制文件，直接下载并赋予执行权限：

```bash
chmod +x gosocks5
```

## 使用方法

### 基本命令

```
gosocks5 <command> [options]
```

### 可用命令

- `start` - 启动 SOCKS5 服务器
- `stop` - 停止 SOCKS5 服务器
- `restart` - 重启 SOCKS5 服务器
- `status` - 查看服务器状态

### 命令行选项

| 选项 | 说明 | 默认值 | 示例 |
|------|------|--------|------|
| `--port` | 服务器监听端口 | 1080 | `--port=1080` |
| `--config` | 配置文件路径（JSON 格式） | 无 | `--config=./config.json` |
| `--auth` | 启用用户认证，格式：`user1:pass1,user2:pass2` | 无（无需认证） | `--auth=admin:password123` |
| `--log` | 启用/禁用日志 | `true` | `--log=true` |
| `--pidfile` | PID 文件路径 | `/tmp/gosocks5.pid` | `--pidfile=/var/run/gosocks5.pid` |

**注意**：如果使用 `--config` 选项，配置文件中的认证和用户信息将优先使用，命令行 `--auth` 选项将被忽略。

## 使用示例

### 1. 启动简单的 SOCKS5 服务器（无需认证）

```bash
# Linux/macOS
./gosocks5 start --port=1080

# Windows
gosocks5.exe start --port=1080
```

服务器将在端口 1080 上监听，无需认证即可使用。

### 2. 启动带用户认证的服务器（命令行方式）

```bash
./gosocks5 start --port=1080 --auth=admin:secret123,user:password456
```

这将创建两个用户：
- 用户名：`admin`，密码：`secret123`
- 用户名：`user`，密码：`password456`

### 2.1. 使用配置文件启动服务器（推荐）

首先创建配置文件 `config.json`：

```json
{
  "port": 1080,
  "auth": true,
  "auth_required": false,
  "web_port": 8080,
  "users": [
    {
      "username": "admin",
      "password": "admin123"
    },
    {
      "username": "user1",
      "password": "password123"
    }
  ],
  "allowed": [],
  "rate_limits": {
    "user1": 1048576
  }
}
```

然后使用配置文件启动：

```bash
./gosocks5 start --config=config.json
```

配置文件格式说明：
- `port`: 服务器端口（可选，会覆盖命令行参数）
- `auth`: 是否启用认证（true/false）
- `auth_required`: 是否强制认证（true/false），当设置为true时，即使客户端支持无认证方法，也必须进行认证
- `web_port`: Web监控面板端口（默认8080）
- `users`: 用户列表，包含 username 和 password
- `allowed`: 允许连接的客户端IP白名单
- `rate_limits`: 用户限速配置，单位为bytes/s

参考 `config.example.json` 查看完整示例。

### 3. 启动带Web监控面板的服务器

在配置文件中设置 `web_port` 参数即可启用Web监控面板：

```json
{
  "port": 1080,
  "web_port": 8080,
  "auth": true,
  "users": [
    {
      "username": "admin",
      "password": "admin123"
    }
  ]
}
```

启动后访问 `http://localhost:8080` 即可查看监控面板。

### 4. 启动带IP白名单的服务器

```json
{
  "port": 1080,
  "auth": true,
  "users": [
    {
      "username": "admin",
      "password": "admin123"
    }
  ],
  "allowed": ["192.168.1.0/24", "10.0.0.0/8"]
}
```

### 5. 后台运行（Linux/macOS）

```bash
nohup ./gosocks5 start --port=1080 --auth=admin:secret123 > /dev/null 2>&1 &
```

### 6. 停止服务器

```bash
./gosocks5 stop
```

### 7. 查看服务器状态

```bash
./gosocks5 status
```

输出示例：
```
server (pid 12345) is running...
```

### 8. 重启服务器

```bash
./gosocks5 restart --port=1080 --auth=admin:secret123
```

## Web监控面板

### 功能特性

- **实时流量监控**：显示总上传和下载速率的实时图表
- **用户统计**：显示在线用户、会话数、流量统计等信息
- **IP统计**：按IP地址统计流量使用情况
- **会话详情**：显示所有活跃会话的详细信息
- **用户阻断**：可以动态阻断或解除阻断用户
- **IP筛选**：可以根据IP地址筛选显示的数据
- **自动刷新**：数据每5秒自动刷新一次

### 使用方法

1. 在配置文件中设置 `web_port` 参数
2. 启动服务器
3. 在浏览器中访问 `http://服务器IP:web_port`

### 界面说明

- **顶部统计卡片**：显示当前活跃会话数和在线用户数
- **实时流量监控图表**：显示上传和下载速率的实时变化
- **用户统计表格**：显示每个用户的会话数、流量统计和操作按钮
- **IP统计表格**：按IP地址显示流量统计信息
- **会话详情表格**：显示所有活跃会话的详细信息

### 用户阻断功能

在用户统计表格中，可以点击"阻断"按钮来阻断某个用户，该用户的所有连接将被立即断开。阻断后的用户可以点击"解除"按钮来解除阻断。

## 客户端配置

### 浏览器配置（以 Firefox 为例）

1. 打开 Firefox 设置
2. 网络设置 → 设置
3. 选择"手动代理配置"
4. SOCKS 主机：`127.0.0.1`，端口：`1080`
5. SOCKS v5
6. 如果启用了认证，勾选"代理 DNS 查询使用 SOCKS v5"（可选）

### 命令行工具配置

#### curl

```bash
# 无需认证
curl --socks5 127.0.0.1:1080 http://example.com

# 需要认证
curl --socks5-hostname 127.0.0.1:1080 --proxy-user admin:secret123 http://example.com
```

#### wget

```bash
# 在 ~/.wgetrc 中配置
proxy = on
http_proxy = socks5://admin:secret123@127.0.0.1:1080
https_proxy = socks5://admin:secret123@127.0.0.1:1080
```

#### SSH

```bash
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" user@remote-host
```

#### Git

```bash
git config --global http.proxy socks5://127.0.0.1:1080
git config --global https.proxy socks5://127.0.0.1:1080
```

### 系统级代理配置（Linux）

```bash
export http_proxy=socks5://127.0.0.1:1080
export https_proxy=socks5://127.0.0.1:1080
export ALL_PROXY=socks5://127.0.0.1:1080
```

## 配置说明

### 超时设置

代码中预定义了以下超时配置（可在源代码中修改）：

- **连接超时**：30 秒
- **读取超时**：5 分钟
- **写入超时**：5 分钟
- **空闲超时**：10 分钟

### 连接限制

- **最大并发连接数**：默认 1000（可在源代码中修改）

### 性能参数

- **缓冲区大小**：32KB（优化后的值，减少内存占用）
- **TCP Keep-Alive**：30 秒间隔

## 日志

服务器会输出详细的连接日志，包括：

### 日志类型

1. **会话日志** (`[SESSION]`): 记录会话的开始和结束
2. **认证日志** (`[AUTH]`): 记录用户登录成功/失败
3. **连接日志** (`[CONNECT]`): 记录代理连接的详细信息
4. **阻断日志** (`[BLOCK]`): 记录用户阻断/解除阻断操作

### 日志示例

```
2024/01/01 12:00:00 SOCKS5 server started on port 1080
2024/01/01 12:00:00 Authentication enabled with 2 user(s)
2024/01/01 12:00:00 Configuration loaded from config.json
2024/01/01 12:00:00 Loaded user from config: admin
2024/01/01 12:00:00 Loaded user from config: user1

[SESSION] Session[1] started from 192.168.1.100:54321
[AUTH] Session[1] from 192.168.1.100:54321: login SUCCESS (username: admin)
[CONNECT] Session[1] user admin from 192.168.1.100:54321 connecting to example.com:80
[CONNECT] Session[1] user admin from 192.168.1.100:54321 successfully connected to example.com:80
[SESSION] Session[1] closed from 192.168.1.100:54321 (user: admin, duration: 30s)

[SESSION] Session[2] started from 192.168.1.100:54322
[AUTH] Session[2] from 192.168.1.100:54322: login FAILED (username: hacker, reason: invalid credentials)
[SESSION] Session[2] closed from 192.168.1.100:54322 (duration: 500ms)

[BLOCK] User testuser has been blocked
[BLOCK] Closing session[3] for blocked user testuser
```

### 日志说明

- **登录成功**: `[AUTH] Session[ID] from [IP]: login SUCCESS (username: [用户名])`
- **登录失败**: `[AUTH] Session[ID] from [IP]: login FAILED (username: [用户名], reason: invalid credentials)`
- **连接建立**: `[CONNECT] Session[ID] user [用户名] from [IP] successfully connected to [目标]:[端口]`
- **连接失败**: `[CONNECT] Session[ID] user [用户名] from [IP] failed to connect to [目标]:[端口]: [错误]`
- **会话关闭**: `[SESSION] Session[ID] closed from [IP] (user: [用户名], duration: [持续时间])`
- **用户阻断**: `[BLOCK] User [用户名] has been blocked`
- **会话关闭（因阻断）**: `[BLOCK] Closing session[ID] for blocked user [用户名]`

要禁用日志，使用 `--log=false`。

## 安全建议

1. **使用认证**：在生产环境中，强烈建议启用用户认证
2. **防火墙**：配置防火墙规则，只允许必要的端口开放
3. **定期更新**：保持代码更新，修复潜在的安全漏洞
4. **密码强度**：使用强密码，避免简单的密码组合
5. **IP白名单**：使用IP白名单限制客户端连接
6. **用户阻断**：及时阻断异常用户

## 限制和已知问题

- ⚠️ **BIND 命令**：暂不支持 SOCKS5 BIND 命令
- ⚠️ **UDP 代理**：暂不支持 UDP ASSOCIATE 命令（UDP 代理）
- ⚠️ **仅支持 TCP**：当前版本仅支持 TCP 连接代理

## 技术架构

- **并发模型**：每个客户端连接使用独立的 goroutine 处理
- **数据传输**：使用高效的双向管道机制（SocketPipe）
- **连接管理**：使用信号量控制并发连接数
- **超时控制**：全面的超时机制防止资源泄漏
- **流量统计**：实时流量统计和速率计算
- **Web监控**：内嵌Web服务器提供实时监控面板

### 故障排除

### 端口被占用

```bash
# Linux/macOS 查看端口占用
lsof -i :1080
netstat -tulpn | grep 1080

# Windows 查看端口占用
netstat -ano | findstr :1080
```

### 连接被拒绝

1. 检查服务器是否运行：`./gosocks5 status`
2. 检查防火墙设置

### 认证失败

1. 确认用户名和密码正确
2. 检查 `--auth` 参数格式是否正确
3. 查看服务器日志

## 开发

### 代码结构

- `UserManager`：用户认证管理
- `Session`：会话管理
- `SocketPipe`：双向数据传输管道
- `SOCKS5Server`：主服务器实现
- `TrafficStats`：流量统计
- `WebServer`：内嵌Web监控服务器

### 编译调试版本

```bash
go build -gcflags="-N -l" -o gosocks5-debug go-socks5.go
```

## 许可证

本项目采用 MIT 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

### 最新版本特性

- ✅ **配置文件支持**：支持从 JSON 配置文件加载用户认证信息
- ✅ **详细日志记录**：
  - 用户登录成功/失败日志 (`[AUTH]`)
  - 用户连接使用日志 (`[CONNECT]`)
  - 会话生命周期日志 (`[SESSION]`)
  - 用户阻断日志 (`[BLOCK]`)
- ✅ **Web监控面板**：内嵌Web服务器提供实时监控界面
- ✅ **流量统计**：实时流量统计和图表展示
- ✅ **用户阻断**：支持动态阻断/解除阻断用户
- ✅ **IP筛选**：支持按IP地址筛选监控数据
- ✅ **用户限速**：支持按用户设置上传/下载速率限制
- ✅ 在 Session 中记录用户名，便于追踪用户活动

### 优化版本特性

- ✅ 修复 `sendReply` 函数的 session 引用错误
- ✅ 优化 SocketPipe 等待机制（使用 channel 替代轮询）
- ✅ 添加连接数限制和超时控制
- ✅ 优化内存使用（缓冲区大小优化）
- ✅ 改进安全性（输入验证、错误处理）
- ✅ 性能优化（减少系统调用、改进数据传输）
- ✅ 修复 Targets 数据结构问题（使用 map 提高查找效率）

## 联系方式

如有问题或建议，请通过 Issue 提交反馈。
