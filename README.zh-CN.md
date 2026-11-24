# TLS 证书检查器 (TLS Certificate Checker)

[English](README.md) | **简体中文**

一个小巧的 Python 命令行工具，**批量**检查一组域名的 HTTPS/TLS 配置：

1. **证书**：能否通过验证（证书链受信任、域名匹配），还有多少天到期，快到期时告警。
2. **协议版本**：服务器接受 TLS 1.0 / 1.1 / 1.2 / 1.3 中的哪些。
3. **弱密码套件**：服务器是否还接受 NULL、EXPORT、匿名、RC4、DES/3DES、MD5，
   或者 RSA 密钥交换（没有前向保密）。

只用标准库，不需要 `pip install`。Python 3.8+。

## 用法

```bash
python3 tls_check.py github.com example.com
python3 tls_check.py example.com:8443 https://www.python.org/downloads/
python3 tls_check.py -f examples/domains.txt      # 每行一个目标，# 是注释
python3 tls_check.py -f domains.txt --no-probe    # 只查证书，快很多
python3 tls_check.py -f domains.txt --warn-days 45 --critical-days 14
python3 tls_check.py intranet.local --cafile company-ca.pem   # 内网自建 CA
python3 tls_check.py -f domains.txt --json        # 机器可读的输出

python3 -m unittest -v                            # 离线测试
```

示例输出：

```
⚠️  example.org:443
   证书: example.org  颁发者: Let's Encrypt  到期: 2026-12-20（剩 26 天）
   协商结果: TLSv1.3  TLS_AES_256_GCM_SHA384
   协议支持: TLSv1.0 ✗  TLSv1.1 ✗  TLSv1.2 ✓  TLSv1.3 ✓
   [警告] 证书 26 天后到期（阈值 30 天）

❌ legacy.example.net:443
   证书: legacy.example.net  颁发者: DigiCert Inc  到期: 2027-03-02（剩 98 天）
   协商结果: TLSv1.2  ECDHE-RSA-AES256-GCM-SHA384
   协议支持: TLSv1.0 ✓  TLSv1.1 ✓  TLSv1.2 ✓  TLSv1.3 ✗
   未能测试的弱套件（本机 OpenSSL 已移除）: EXPORT, RC4, DES
   [警告] 仍支持已废弃的 TLSv1.0（RFC 8996）
   [警告] 仍支持已废弃的 TLSv1.1（RFC 8996）
   [警告] 接受弱套件 AES256-SHA — RSA 密钥交换：没有前向保密…
   [提示] 不支持 TLS 1.3

⚠️  检查了 2 个目标，2 个有问题。
```

| 等级 | 触发条件 |
|---|---|
| 严重 | 连不上；证书验证失败（不受信任、自签名、域名不匹配、已过期）；7 天内到期；还没到生效时间；TLS 1.2 和 1.3 都不支持；接受 NULL / EXPORT / 匿名 / RC4 / DES / 3DES / MD5 |
| 警告 | 30 天内到期；开着 TLS 1.0 或 1.1；RSA 密钥交换（无前向保密） |
| 提示 | 不支持 TLS 1.3 |

| 退出码 | 含义 |
|---|---|
| `0` | 没有警告或严重问题（只有提示也算正常） |
| `1` | 至少一个目标有警告或严重问题（适合放进 cron / CI） |
| `2` | 参数错误或目标文件读不了 |

## 原理

```
目标 ─► 解析 host:port
   │
   ├─ 1. 完整验证的握手（系统 CA 证书库 + 域名校验）
   │       成功 → 拿到解析好的证书、协商出的版本和套件
   │       失败 → 记下原因，再用“不验证”的方式握手一次，
   │              照样读出证书（到期时间、颁发者…）
   │
   ├─ 2. 每个协议版本握手一次，min_version = max_version = 该版本
   │
   └─ 3. 每类弱套件握手一次，TLS ≤ 1.2，set_ciphers("RC4") 之类
           握手成功 = 服务器接受这一类套件
                         ▼
            evaluate() → 问题列表 → 文本 / JSON、退出码
```

### 设计说明

- **整个测试就是“握手能不能成功”。** 没法直接问服务器“你支持哪些套件”，只能只提供想测的那一项，
  看服务器肯不肯接。`sslscan`、`testssl.sh` 也是这么做的，只是组合多得多。
- **TLS 1.3 不测弱套件。** TLS 1.3 的 5 个套件全是 AEAD（AES-GCM、ChaCha20-Poly1305、AES-CCM），
  而且天生带前向保密。
- **三值结果。** 每个探测返回“是 / 否 / 未知”。新版 OpenSSL 直接删掉了 RC4、EXPORT，
  很多版本连 3DES 也删了，客户端**根本发不出**这些套件。这时结果记为“未知”并列为未测试，
  绝不报告成“服务器不支持”，否则就是一个虚假的“一切正常”。
- **老协议探测用 `@SECLEVEL=0`。** OpenSSL 3 在默认安全等级下连 TLS 1.0 的握手都不肯发。
  只在探测连接上降低等级，让客户端能问出口；做证书验证的主连接仍用正常默认值。
- **验证失败也能看到证书详情。** Python 只会解析验证通过的连接的证书。验证失败时，
  工具拿原始 DER 字节，用 CPython 内部的 `ssl._ssl._test_decode_cert`（`ssl` 模块自己的测试也在用）解析。
  这个函数不可用时，只是少了证书详情，其他检查不受影响。
- **并发。** 多个目标并行检查（`-w`，默认 8）。同一个目标的探测按顺序进行，
  不会对一台服务器瞬间发起一大堆握手。
- **离线测试。** 评级逻辑是纯函数，用假证书数据测。握手和探测逻辑在 `127.0.0.1` 上起一个临时 TLS
  服务器来测，CA 和证书在测试时用 `openssl` 命令现场生成（没有 `openssl` 就跳过）。

## 局限

- **能测什么由本机 OpenSSL 决定。** 本机没有 RC4，就判断不了服务器是否接受 RC4。报告会把这些列为未测试。
- **不检查密钥长度和签名算法。** 标准库拿不到对端证书的公钥和签名算法。需要的话用
  `openssl s_client -connect host:443 | openssl x509 -noout -text`。
- **不检查吊销状态（OCSP/CRL）、CT 日志、HSTS、证书链顺序。**
- **只按“类别”探测弱套件**，不是逐个套件；TLS 1.2 里的 CBC 模式、SHA-1 MAC 套件不会被标记。
- **不支持 STARTTLS。** 只适用于一上来就是 TLS 的服务（HTTPS、IMAPS、465 端口的 SMTPS…），
  25/587 端口用 STARTTLS 的 SMTP 不行。
- **中间设备会改变结果。** 如果网络里有做 TLS 解密的代理，看到的是代理的证书和配置，而不是真实服务器的。
- 只检查你自己的、或者获得授权的服务器。大部分是普通握手，但一连串故意用弱套件的握手可能会出现在安全团队的日志里。

## 现实中的同类工具

[`testssl.sh`](https://github.com/drwetter/testssl.sh)、
[`sslscan`](https://github.com/rbsec/sslscan)、
[SSL Labs Server Test](https://www.ssllabs.com/ssltest/)、`nmap --script ssl-enum-ciphers`，
以及 Uptime Kuma 这类证书到期监控。这个项目是同一思路的学习版。
