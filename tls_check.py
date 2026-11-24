#!/usr/bin/env python3
"""
TLS 证书检查器 (TLS Certificate Checker)

批量检查一组域名的 HTTPS/TLS 配置：
  1. 证书：是否能通过验证（受信任、域名匹配）、还有多少天到期，快到期时告警；
  2. 协议版本：服务器支持 TLS 1.0 / 1.1 / 1.2 / 1.3 中的哪些；
  3. 弱密码套件：服务器是否还接受 NULL、EXPORT、RC4、DES/3DES、匿名、MD5、
     无前向保密（RSA 密钥交换）这类不安全的套件。

做法很直接：对每个协议版本、每类弱套件，各发起一次只允许它的 TLS 握手，
握手成功 = 服务器支持。只依赖 Python 标准库，Python 3.8+ 可直接运行。
"""

import argparse
import concurrent.futures
import json
import os
import socket
import ssl
import sys
import tempfile
import time
import warnings
from datetime import datetime, timezone

DEFAULT_PORT = 443
DEFAULT_WARN_DAYS = 30
DEFAULT_CRITICAL_DAYS = 7

# 等级从高到低
CRITICAL, WARNING, INFO = "critical", "warning", "info"
LEVEL_LABEL = {CRITICAL: "严重", WARNING: "警告", INFO: "提示"}
LEVEL_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}

# 逐个探测的协议版本。TLS 1.0 / 1.1 已在 2021 年被 RFC 8996 正式废弃。
PROTOCOLS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]
DEPRECATED_PROTOCOLS = {"TLSv1.0", "TLSv1.1"}

# 弱密码套件类别：(编号, OpenSSL 套件字符串, 等级, 说明)
# TLS 1.3 的 5 个套件全都是安全的 AEAD 套件，所以弱套件只需在 TLS 1.2 及以下探测。
WEAK_CIPHER_GROUPS = [
    ("NULL", "eNULL", CRITICAL, "NULL 套件：完全不加密，明文传输"),
    ("EXPORT", "EXP", CRITICAL, "EXPORT 出口级套件：40/56 位密钥，可被快速破解（FREAK/Logjam）"),
    ("ANON", "aNULL", CRITICAL, "匿名套件：不验证服务器身份，可被中间人攻击"),
    ("RC4", "RC4", CRITICAL, "RC4：流密码存在统计偏差，已被 RFC 7465 禁用"),
    ("DES", "DES:3DES", CRITICAL, "DES/3DES：64 位分组，易受 SWEET32 攻击"),
    ("MD5", "MD5", CRITICAL, "MD5 做消息认证：哈希已被攻破"),
    ("NO_PFS", "kRSA", WARNING, "RSA 密钥交换：没有前向保密，私钥泄露后历史流量可被解密"),
]

# 表示“本机 OpenSSL 做不到”的错误原因，这时结果记为“未知”而不是“不支持”
LOCAL_UNSUPPORTED_REASONS = {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE",
                             "NO_SUITABLE_SIGNATURE_ALGORITHM"}


# ---------------------------------------------------------------- 目标解析

def parse_target(text, default_port=DEFAULT_PORT):
    """把各种写法统一成 (host, port)。

    支持: example.com / example.com:8443 / https://example.com/path /
          1.2.3.4:443 / [::1]:443 / ::1
    """
    t = text.strip()
    if not t:
        raise ValueError("空目标")
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in t:  # user:pass@host
        t = t.rsplit("@", 1)[1]
    port = default_port
    if t.startswith("["):  # [IPv6]:port
        end = t.find("]")
        if end == -1:
            raise ValueError(f"无法解析: {text}")
        host, rest = t[1:end], t[end + 1:]
        if rest.startswith(":"):
            port = int(rest[1:])
    elif t.count(":") == 1:
        host, p = t.split(":")
        port = int(p)
    else:  # 普通域名，或者不带端口的裸 IPv6
        host = t
    host = host.strip().rstrip(".").lower()
    if not host or not (0 < port < 65536):
        raise ValueError(f"无法解析: {text}")
    return host, port


def read_targets_file(path):
    """读目标列表文件：每行一个，# 后面是注释，空行忽略。"""
    targets = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                targets.append(line)
    return targets


# ---------------------------------------------------------------- 证书

def _name_to_dict(name):
    """getpeercert() 里的 subject/issuer 是嵌套元组，转成 {字段: 值}。"""
    out = {}
    for rdn in name or ():
        for key, value in rdn:
            out.setdefault(key, value)
    return out


def summarize_cert(cert):
    """把 getpeercert() 的字典整理成报告里要用的几项。"""
    if not cert:
        return None
    subject = _name_to_dict(cert.get("subject"))
    issuer = _name_to_dict(cert.get("issuer"))
    sans = [v for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
    return {
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "san": sans,
        "serial": cert.get("serialNumber"),
    }


def decode_der_cert(der):
    """验证失败时拿不到解析好的证书，只能拿到 DER 原始字节。

    标准库没有公开的 DER 解析函数，这里借用 CPython 内部的
    ssl._ssl._test_decode_cert（ssl 模块自己的测试也在用它）。
    不可用时返回 None，报告里只是少了证书详情，其他检查不受影响。
    """
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if not der or decode is None:
        return None
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        return decode(path)
    except Exception:
        return None
    finally:
        os.unlink(path)


def days_left(not_after, now=None):
    """距离到期还有多少天（可能是负数 = 已过期）。"""
    if now is None:
        now = time.time()
    return (ssl.cert_time_to_seconds(not_after) - now) / 86400


def fmt_cert_time(value):
    ts = ssl.cert_time_to_seconds(value)
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------- 网络

def _client_context(verify, cafile=None, min_version=None, max_version=None,
                    ciphers=None):
    if verify:
        ctx = ssl.create_default_context(cafile=cafile)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        # 设置 TLS 1.0/1.1 会触发 DeprecationWarning；这里是故意探测，静音即可
        warnings.simplefilter("ignore", DeprecationWarning)
        if min_version is not None:
            ctx.minimum_version = min_version
        if max_version is not None:
            ctx.maximum_version = max_version
    if ciphers is not None:
        ctx.set_ciphers(ciphers)  # 本机 OpenSSL 没有任何匹配的套件时抛 SSLError
    return ctx


def _handshake(host, port, ctx, timeout):
    """完成一次 TLS 握手，返回 (协议版本, 套件名, 已解析证书, DER 证书)。"""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return (tls.version(), tls.cipher()[0],
                    tls.getpeercert(), tls.getpeercert(binary_form=True))


def try_handshake(host, port, ctx, timeout):
    """探测用：握手成功返回套件名；服务器拒绝返回 False；
    本机 OpenSSL 做不到返回 None（无法判断）。网络错误照常抛出。"""
    try:
        return _handshake(host, port, ctx, timeout)[1]
    except ssl.SSLError as e:
        if getattr(e, "reason", None) in LOCAL_UNSUPPORTED_REASONS:
            return None
        return False
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, EOFError):
        # 很多服务器遇到不支持的握手时直接断开连接
        return False


def probe_protocols(host, port, timeout):
    """逐个版本握手，返回 {"TLSv1.2": True/False/None, ...}。"""
    result = {}
    for name, version in PROTOCOLS:
        try:
            # SECLEVEL=0：允许本机 OpenSSL 发出老版本握手，否则它自己就先拒绝了
            ciphers = "ALL:@SECLEVEL=0" if version < ssl.TLSVersion.TLSv1_2 else None
            ctx = _client_context(False, min_version=version, max_version=version,
                                  ciphers=ciphers)
        except (ValueError, ssl.SSLError):
            result[name] = None
            continue
        ok = try_handshake(host, port, ctx, timeout)
        result[name] = None if ok is None else bool(ok)
    return result


def probe_weak_ciphers(host, port, timeout):
    """每类弱套件单独握手一次。返回 {类别: 套件名 / False / None}。"""
    result = {}
    for key, spec, _level, _desc in WEAK_CIPHER_GROUPS:
        try:
            ctx = _client_context(False, min_version=ssl.TLSVersion.TLSv1,
                                  max_version=ssl.TLSVersion.TLSv1_2,
                                  ciphers=spec + ":@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            result[key] = None  # 本机 OpenSSL 编译时就去掉了这类套件，没法测
            continue
        result[key] = try_handshake(host, port, ctx, timeout)
    return result


def check_host(host, port, timeout=5.0, cafile=None, probe=True):
    """检查一个目标，返回原始结果字典（还没有评级）。"""
    r = {"host": host, "port": port, "error": None, "verified": False,
         "verify_error": None, "protocol": None, "cipher": None, "cert": None,
         "protocols": None, "weak_ciphers": None}
    try:
        try:
            version, cipher, cert, _der = _handshake(
                host, port, _client_context(True, cafile=cafile), timeout)
            r["verified"] = True
        except ssl.SSLCertVerificationError as e:
            # 证书有问题（过期 / 自签名 / 域名不匹配…）。记下原因，
            # 再用不验证的方式连一次，把证书拿出来看看。
            r["verify_error"] = e.verify_message or str(e)
            version, cipher, _cert, der = _handshake(
                host, port, _client_context(False), timeout)
            cert = decode_der_cert(der)
        r["protocol"], r["cipher"] = version, cipher
        r["cert"] = summarize_cert(cert)
        if probe:
            r["protocols"] = probe_protocols(host, port, timeout)
            r["weak_ciphers"] = probe_weak_ciphers(host, port, timeout)
    except (OSError, ssl.SSLError) as e:  # 包括 DNS 失败、超时、拒绝连接、握手失败
        r["error"] = f"{type(e).__name__}: {e}"
    return r


# ---------------------------------------------------------------- 评级

def evaluate(r, warn_days=DEFAULT_WARN_DAYS, critical_days=DEFAULT_CRITICAL_DAYS,
             now=None):
    """根据原始结果给出问题列表 [(等级, 说明), ...]。纯函数，方便离线测试。"""
    findings = []
    if r.get("error"):
        return [(CRITICAL, f"无法完成 TLS 连接: {r['error']}")]

    if not r.get("verified"):
        findings.append((CRITICAL, f"证书验证失败: {r.get('verify_error')}"))

    cert = r.get("cert")
    if cert and cert.get("not_after"):
        left = days_left(cert["not_after"], now)
        if left < 0:
            findings.append((CRITICAL, f"证书已过期 {int(-left)} 天"))
        elif left < critical_days:
            findings.append((CRITICAL, f"证书 {left:.1f} 天后到期"))
        elif left < warn_days:
            findings.append((WARNING, f"证书 {int(left)} 天后到期（阈值 {warn_days} 天）"))
        if cert.get("not_before") and days_left(cert["not_before"], now) > 0:
            findings.append((CRITICAL, "证书还没到生效时间"))

    protos = r.get("protocols")
    if protos:
        for name in sorted(DEPRECATED_PROTOCOLS):
            if protos.get(name):
                findings.append((WARNING, f"仍支持已废弃的 {name}（RFC 8996）"))
        if protos.get("TLSv1.2") is False and protos.get("TLSv1.3") is False:
            findings.append((CRITICAL, "不支持 TLS 1.2 和 TLS 1.3"))
        elif protos.get("TLSv1.3") is False:
            findings.append((INFO, "不支持 TLS 1.3"))

    weak = r.get("weak_ciphers")
    if weak:
        for key, _spec, level, desc in WEAK_CIPHER_GROUPS:
            if weak.get(key):
                findings.append((level, f"接受弱套件 {weak[key]} — {desc}"))

    findings.sort(key=lambda f: LEVEL_ORDER[f[0]])
    return findings


def worst_level(findings):
    return min((f[0] for f in findings), key=LEVEL_ORDER.get, default=None)


# ---------------------------------------------------------------- 输出

def _mark(v):
    return {True: "✓", False: "✗", None: "?"}[v]


def format_report(r, findings, now=None):
    worst = worst_level(findings)
    icon = {CRITICAL: "❌", WARNING: "⚠️ ", INFO: "✅", None: "✅"}[worst]
    lines = [f"{icon} {r['host']}:{r['port']}"]
    cert = r.get("cert")
    if cert:
        exp = ""
        if cert.get("not_after"):
            left = days_left(cert["not_after"], now)
            when = f"剩 {int(left)} 天" if left >= 0 else f"已过期 {int(-left)} 天"
            exp = f"  到期: {fmt_cert_time(cert['not_after'])}（{when}）"
        lines.append(f"   证书: {cert['subject'] or '-'}  颁发者: {cert['issuer'] or '-'}{exp}")
    if r.get("protocol"):
        lines.append(f"   协商结果: {r['protocol']}  {r['cipher']}")
    if r.get("protocols"):
        lines.append("   协议支持: " + "  ".join(
            f"{n} {_mark(v)}" for n, v in r["protocols"].items()))
    untested = [k for k, v in (r.get("weak_ciphers") or {}).items() if v is None]
    if untested:
        lines.append("   未能测试的弱套件（本机 OpenSSL 已移除）: " + ", ".join(untested))
    for level, msg in findings:
        lines.append(f"   [{LEVEL_LABEL[level]}] {msg}")
    return "\n".join(lines)


def to_json(results):
    return json.dumps([
        dict(r, findings=[{"level": lv, "message": m} for lv, m in fs])
        for r, fs in results
    ], ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- 命令行

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="批量检查域名的 TLS 证书到期时间、协议版本和弱密码套件。")
    parser.add_argument("targets", nargs="*",
                        help="域名，可写成 host、host:port 或 https://host/...")
    parser.add_argument("-f", "--file", help="从文件读目标，每行一个，# 开头是注释")
    parser.add_argument("--warn-days", type=int, default=DEFAULT_WARN_DAYS,
                        help=f"剩余天数少于这个值时警告（默认 {DEFAULT_WARN_DAYS}）")
    parser.add_argument("--critical-days", type=int, default=DEFAULT_CRITICAL_DAYS,
                        help=f"剩余天数少于这个值时算严重（默认 {DEFAULT_CRITICAL_DAYS}）")
    parser.add_argument("--no-probe", action="store_true",
                        help="只检查证书，不逐个探测协议版本和弱套件（快很多）")
    parser.add_argument("--timeout", type=float, default=5.0, help="每次连接超时秒数（默认 5）")
    parser.add_argument("-w", "--workers", type=int, default=8, help="并发检查的目标数（默认 8）")
    parser.add_argument("--cafile", help="额外信任的 CA 证书（PEM），用于内网自建 CA")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    raw = list(args.targets)
    try:
        if args.file:
            raw += read_targets_file(args.file)
        targets = list(dict.fromkeys(parse_target(t) for t in raw))  # 去重保序
    except (OSError, ValueError) as e:
        print(f"错误: {e}", file=sys.stderr)
        return 2
    if not targets:
        parser.print_usage(sys.stderr)
        print("错误: 至少要给一个目标（参数或 -f 文件）", file=sys.stderr)
        return 2

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        raw_results = list(pool.map(
            lambda hp: check_host(hp[0], hp[1], timeout=args.timeout,
                                  cafile=args.cafile, probe=not args.no_probe),
            targets))
    results = [(r, evaluate(r, args.warn_days, args.critical_days)) for r in raw_results]

    if args.json:
        print(to_json(results))
    else:
        for r, fs in results:
            print(format_report(r, fs))
            print()
        bad = sum(1 for _, fs in results if worst_level(fs) in (CRITICAL, WARNING))
        if bad:
            print(f"⚠️  检查了 {len(results)} 个目标，{bad} 个有问题。")
        else:
            print(f"✅ 检查了 {len(results)} 个目标，没有发现问题。")

    return 1 if any(worst_level(fs) in (CRITICAL, WARNING) for _, fs in results) else 0


if __name__ == "__main__":
    sys.exit(main())
