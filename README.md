# TLS Certificate Checker

**English** | [简体中文](README.zh-CN.md)

A small Python CLI that checks the HTTPS/TLS setup of **many domains at once**:

1. **Certificate**: does it verify (trusted chain, hostname matches), and how many days
   until it expires? Warns when expiry is near.
2. **Protocol versions**: which of TLS 1.0 / 1.1 / 1.2 / 1.3 the server accepts.
3. **Weak cipher suites**: whether the server still accepts NULL, EXPORT, anonymous,
   RC4, DES/3DES, MD5, or RSA key exchange (no forward secrecy).

Standard library only: no `pip install`. Python 3.8+.

## Usage

```bash
python3 tls_check.py github.com example.com
python3 tls_check.py example.com:8443 https://www.python.org/downloads/
python3 tls_check.py -f examples/domains.txt      # one target per line, # comments
python3 tls_check.py -f domains.txt --no-probe    # certificate only, much faster
python3 tls_check.py -f domains.txt --warn-days 45 --critical-days 14
python3 tls_check.py intranet.local --cafile company-ca.pem   # internal CA
python3 tls_check.py -f domains.txt --json        # machine-readable

python3 -m unittest -v                            # offline tests
```

Example output (the CLI prints in Chinese):

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

`证书` = certificate, `颁发者` = issuer, `到期` / `剩 N 天` = expires / N days left,
`协商结果` = negotiated, `协议支持` = protocol support, `严重 / 警告 / 提示` =
critical / warning / info.

| Level | Raised for |
|---|---|
| critical | Can't connect; verification failed (untrusted, self-signed, hostname mismatch, expired); expires in < 7 days; not yet valid; no TLS 1.2 or 1.3; accepts NULL / EXPORT / anon / RC4 / DES / 3DES / MD5 |
| warning | Expires in < 30 days; TLS 1.0 or 1.1 enabled; RSA key exchange (no forward secrecy) |
| info | No TLS 1.3 |

| Exit code | Meaning |
|---|---|
| `0` | No warnings or critical findings (info is fine) |
| `1` | At least one target has a warning or critical finding (handy for cron / CI) |
| `2` | Bad arguments or unreadable target file |

## How it works

```
target ─► parse host:port
   │
   ├─ 1. handshake with full verification (system CA store, hostname check)
   │       ok   → keep parsed certificate, negotiated version and cipher
   │       fail → record the reason, handshake again WITHOUT verification
   │              to still read the certificate (expiry, issuer…)
   │
   ├─ 2. one handshake per protocol version, min_version = max_version = v
   │
   └─ 3. one handshake per weak-cipher family, TLS ≤ 1.2, set_ciphers("RC4") etc.
           handshake succeeds = the server accepts that family
                         ▼
            evaluate() → findings → text / JSON, exit code
```

### Design notes

- **"Does the handshake succeed?" is the whole test.** Asking a server which ciphers it
  supports isn't possible; you offer only the thing you want to test and see if the
  server agrees. That's what tools like `sslscan` and `testssl.sh` do too, just with
  far more combinations.
- **TLS 1.3 isn't probed for weak ciphers.** All five TLS 1.3 suites are AEAD
  (AES-GCM, ChaCha20-Poly1305, AES-CCM) with forward secrecy by design.
- **Three-valued results.** Every probe returns *yes*, *no*, or *unknown*. Modern
  OpenSSL builds remove RC4, EXPORT and (often) 3DES entirely, so the client *can't
  offer* them. In that case the result is "unknown" and listed as untested, never
  reported as "server doesn't support it", which would be a false all-clear.
- **`@SECLEVEL=0` for old probes.** OpenSSL 3 refuses to even send a TLS 1.0 hello at
  its default security level. Lowering it only for the probe connections lets the
  client ask; the verified main connection uses normal defaults.
- **Certificate details even when verification fails.** Python only parses the
  certificate of a verified connection. For a failed one, the tool takes the raw DER
  bytes and decodes them with CPython's internal `ssl._ssl._test_decode_cert` (the one
  `ssl`'s own tests use). If that isn't available, only the details are missing.
- **Concurrency.** Targets are checked in parallel (`-w`, default 8). Probes for one
  target run in sequence so a single server isn't hit with a burst of handshakes.
- **Offline tests.** Rating logic is a pure function tested with fake certificates.
  Handshake and probing are tested against a throwaway TLS server on `127.0.0.1`
  whose CA and certificate are generated with the `openssl` command at test time
  (skipped if `openssl` is missing).

## Limitations

- **Your local OpenSSL decides what can be tested.** If it has no RC4, the tool can't
  tell whether a server accepts RC4. The report lists these as untested.
- **No key size or signature algorithm check.** The standard library doesn't expose
  the public key or signature algorithm of a peer certificate. Use
  `openssl s_client -connect host:443 | openssl x509 -noout -text` for those.
- **No revocation (OCSP/CRL), CT log, HSTS, or certificate chain-order checks.**
- **Only "families" of weak ciphers are probed**, not every individual suite, and CBC
  mode / SHA-1 MAC suites in TLS 1.2 aren't flagged.
- **No STARTTLS.** Only services that speak TLS from the first byte (HTTPS, IMAPS,
  SMTPS on 465…) work; SMTP on 25/587 with STARTTLS doesn't.
- **Middleboxes change the result.** Behind a TLS-inspecting proxy you'll see the
  proxy's certificate and settings, not the real server's.
- Only check servers you own or are allowed to test. It's mostly normal handshakes,
  but a burst of deliberately weak ones can show up in a security team's logs.

## Real-world equivalents

[`testssl.sh`](https://github.com/drwetter/testssl.sh),
[`sslscan`](https://github.com/rbsec/sslscan),
[SSL Labs Server Test](https://www.ssllabs.com/ssltest/), `nmap --script ssl-enum-ciphers`,
and certificate expiry monitors like Uptime Kuma. This project is a learning-sized
version of the same idea.
