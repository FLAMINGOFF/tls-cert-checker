"""离线测试：不访问外网。运行: python3 -m unittest -v

- 评级逻辑用假的证书数据测（纯函数，不需要网络）；
- 握手/探测逻辑在本机 127.0.0.1 起一个临时 TLS 服务器来测，
  证书用 openssl 命令现场生成；没有 openssl 命令时自动跳过这部分。
"""
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

import tls_check as t

NOW = ssl.cert_time_to_seconds("Jun  1 00:00:00 2026 GMT")


def fake_result(**kw):
    r = {"host": "example.com", "port": 443, "error": None, "verified": True,
         "verify_error": None, "protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256",
         "cert": {"subject": "example.com", "issuer": "Test CA",
                  "not_before": "Jan  1 00:00:00 2026 GMT",
                  "not_after": "Dec 31 00:00:00 2026 GMT", "san": [], "serial": "01"},
         "protocols": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
         "weak_ciphers": {k: False for k, *_ in t.WEAK_CIPHER_GROUPS}}
    r.update(kw)
    return r


def with_expiry(not_after):
    r = fake_result()
    r["cert"] = dict(r["cert"], not_after=not_after)
    return r


class TestParseTarget(unittest.TestCase):
    def test_forms(self):
        cases = {
            "example.com": ("example.com", 443),
            "Example.COM.": ("example.com", 443),
            "example.com:8443": ("example.com", 8443),
            "https://example.com/login?x=1": ("example.com", 443),
            "https://user:pw@example.com:9443/": ("example.com", 9443),
            "1.2.3.4:443": ("1.2.3.4", 443),
            "[::1]:8443": ("::1", 8443),
            "::1": ("::1", 443),
        }
        for text, want in cases.items():
            self.assertEqual(t.parse_target(text), want, text)

    def test_bad(self):
        for text in ["", "   ", "example.com:0", "example.com:99999", "[::1"]:
            with self.assertRaises(ValueError, msg=text):
                t.parse_target(text)

    def test_targets_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# 注释\nexample.com\n\n  a.example.org:8443  # 行尾注释\n")
        try:
            self.assertEqual(t.read_targets_file(f.name),
                             ["example.com", "a.example.org:8443"])
        finally:
            os.unlink(f.name)


class TestEvaluate(unittest.TestCase):
    def levels(self, r, **kw):
        return [lv for lv, _ in t.evaluate(r, now=NOW, **kw)]

    def test_healthy(self):
        self.assertEqual(t.evaluate(fake_result(), now=NOW), [])

    def test_expiry_thresholds(self):
        self.assertEqual(self.levels(with_expiry("May 25 00:00:00 2026 GMT")), [t.CRITICAL])  # 已过期
        self.assertEqual(self.levels(with_expiry("Jun  4 00:00:00 2026 GMT")), [t.CRITICAL])  # 3 天
        self.assertEqual(self.levels(with_expiry("Jun 21 00:00:00 2026 GMT")), [t.WARNING])   # 20 天
        self.assertEqual(self.levels(with_expiry("Jul 31 00:00:00 2026 GMT")), [])            # 60 天
        # 阈值可调
        self.assertEqual(self.levels(with_expiry("Jul 31 00:00:00 2026 GMT"), warn_days=90),
                         [t.WARNING])

    def test_expired_message(self):
        msgs = [m for _, m in t.evaluate(with_expiry("May 22 00:00:00 2026 GMT"), now=NOW)]
        self.assertTrue(any("已过期 10 天" in m for m in msgs), msgs)

    def test_not_yet_valid(self):
        r = fake_result()
        r["cert"] = dict(r["cert"], not_before="Jul  1 00:00:00 2026 GMT")
        self.assertIn(t.CRITICAL, self.levels(r))

    def test_verify_failure(self):
        r = fake_result(verified=False, verify_error="self-signed certificate")
        fs = t.evaluate(r, now=NOW)
        self.assertEqual(fs[0][0], t.CRITICAL)
        self.assertIn("self-signed", fs[0][1])

    def test_connection_error(self):
        fs = t.evaluate(fake_result(error="TimeoutError: timed out"), now=NOW)
        self.assertEqual(fs, [(t.CRITICAL, "无法完成 TLS 连接: TimeoutError: timed out")])

    def test_protocols(self):
        r = fake_result(protocols={"TLSv1.0": True, "TLSv1.1": True,
                                   "TLSv1.2": True, "TLSv1.3": False})
        self.assertEqual(self.levels(r), [t.WARNING, t.WARNING, t.INFO])
        r = fake_result(protocols={"TLSv1.0": True, "TLSv1.1": False,
                                   "TLSv1.2": False, "TLSv1.3": False})
        self.assertEqual(self.levels(r)[0], t.CRITICAL)

    def test_unknown_protocol_is_not_reported(self):
        # None = 本机测不了，不能当成“服务器不支持”
        r = fake_result(protocols={"TLSv1.0": None, "TLSv1.1": None,
                                   "TLSv1.2": True, "TLSv1.3": None})
        self.assertEqual(self.levels(r), [])

    def test_weak_ciphers(self):
        weak = {k: False for k, *_ in t.WEAK_CIPHER_GROUPS}
        weak.update(RC4="RC4-SHA", NO_PFS="AES128-SHA", NULL=None)
        fs = t.evaluate(fake_result(weak_ciphers=weak), now=NOW)
        self.assertEqual([lv for lv, _ in fs], [t.CRITICAL, t.WARNING])
        self.assertIn("RC4-SHA", fs[0][1])

    def test_sorted_by_severity(self):
        r = fake_result(protocols={"TLSv1.0": True, "TLSv1.1": False,
                                   "TLSv1.2": True, "TLSv1.3": False},
                        verified=False, verify_error="x")
        lv = self.levels(r)
        self.assertEqual(lv, sorted(lv, key=t.LEVEL_ORDER.get))


class TestCertHelpers(unittest.TestCase):
    def test_summarize(self):
        cert = {"subject": ((("countryName", "US"),), (("commonName", "example.com"),)),
                "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R3"),)),
                "notBefore": "Jan  1 00:00:00 2026 GMT", "notAfter": "Apr  1 00:00:00 2026 GMT",
                "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com"))}
        s = t.summarize_cert(cert)
        self.assertEqual(s["subject"], "example.com")
        self.assertEqual(s["issuer"], "Let's Encrypt")
        self.assertEqual(s["san"], ["example.com", "www.example.com"])
        self.assertIsNone(t.summarize_cert({}))

    def test_days_left(self):
        self.assertAlmostEqual(t.days_left("Jun 11 00:00:00 2026 GMT", NOW), 10)


# ------------------------------------------------------------ 本机 TLS 服务器

class LocalTLSServer:
    """在 127.0.0.1 随机端口上反复接受 TLS 握手，直到 stop()。"""

    def __init__(self, ctx):
        self.ctx = ctx
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            try:
                conn.settimeout(2)
                with self.ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)  # 等客户端关闭
            except (OSError, ssl.SSLError):
                pass
            finally:
                conn.close()

    def stop(self):
        self.running = False
        self.thread.join()
        self.sock.close()


def openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@unittest.skipUnless(shutil.which("openssl"), "没有 openssl 命令，跳过本机握手测试")
class TestLocalServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        d = cls.dir
        # 自建 CA，再用它签一张 localhost / 127.0.0.1 的证书（20 天有效期）
        # 新版 Python 默认开启严格校验（VERIFY_X509_STRICT），CA 必须带 keyUsage 等扩展
        with open(os.path.join(d, "ca.cnf"), "w") as f:
            f.write("[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\n"
                    "[v3_ca]\nbasicConstraints=critical,CA:TRUE\n"
                    "keyUsage=critical,keyCertSign,cRLSign\n"
                    "subjectKeyIdentifier=hash\n")
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
                "-out", "ca.pem", "-days", "30", "-subj", "/CN=Test CA",
                "-config", "ca.cnf", cwd=d)
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key",
                "-out", "leaf.csr", "-subj", "/CN=localhost", cwd=d)
        with open(os.path.join(d, "ext.cnf"), "w") as f:
            f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                    "basicConstraints=CA:FALSE\n"
                    "keyUsage=critical,digitalSignature,keyEncipherment\n"
                    "extendedKeyUsage=serverAuth\n"
                    "subjectKeyIdentifier=hash\n"
                    "authorityKeyIdentifier=keyid\n")
        openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-out", "leaf.pem", "-days", "20",
                "-extfile", "ext.cnf", cwd=d)
        cls.ca = os.path.join(d, "ca.pem")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def server(self, min_v=None, max_v=None, ciphers=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(self.dir, "leaf.pem"),
                            os.path.join(self.dir, "leaf.key"))
        if min_v:
            ctx.minimum_version = min_v
        if max_v:
            ctx.maximum_version = max_v
        if ciphers:
            ctx.set_ciphers(ciphers)
        srv = LocalTLSServer(ctx)
        self.addCleanup(srv.stop)
        return srv

    def test_trusted_cert_and_expiry_warning(self):
        srv = self.server()
        r = t.check_host("127.0.0.1", srv.port, timeout=3, cafile=self.ca)
        self.assertIsNone(r["error"])
        self.assertTrue(r["verified"], r["verify_error"])
        self.assertEqual(r["cert"]["subject"], "localhost")
        self.assertTrue(r["protocols"]["TLSv1.2"])
        self.assertTrue(r["protocols"]["TLSv1.3"])
        levels = [lv for lv, _ in t.evaluate(r)]
        self.assertIn(t.WARNING, levels)        # 20 天 < 30 天阈值
        self.assertNotIn(t.CRITICAL, levels)

    def test_untrusted_cert_still_reports_details(self):
        srv = self.server()
        r = t.check_host("127.0.0.1", srv.port, timeout=3, probe=False)  # 不给 CA
        self.assertFalse(r["verified"])
        self.assertTrue(r["verify_error"])
        self.assertEqual(t.evaluate(r)[0][0], t.CRITICAL)
        if r["cert"]:  # 依赖 CPython 内部函数，拿不到也不算错
            self.assertEqual(r["cert"]["subject"], "localhost")

    def test_tls12_only_server(self):
        srv = self.server(min_v=ssl.TLSVersion.TLSv1_2, max_v=ssl.TLSVersion.TLSv1_2)
        protos = t.probe_protocols("127.0.0.1", srv.port, 3)
        self.assertTrue(protos["TLSv1.2"])
        self.assertFalse(protos["TLSv1.3"])
        self.assertNotEqual(protos["TLSv1.0"], True)

    def test_detects_rsa_key_exchange(self):
        srv = self.server(max_v=ssl.TLSVersion.TLSv1_2, ciphers="AES128-SHA:@SECLEVEL=0")
        weak = t.probe_weak_ciphers("127.0.0.1", srv.port, 3)
        self.assertEqual(weak["NO_PFS"], "AES128-SHA")
        self.assertFalse(weak["DES"] is True)

    def test_modern_server_has_no_weak_ciphers(self):
        srv = self.server(min_v=ssl.TLSVersion.TLSv1_2,
                          ciphers="ECDHE+AESGCM:ECDHE+CHACHA20")
        weak = t.probe_weak_ciphers("127.0.0.1", srv.port, 3)
        self.assertFalse(any(weak.values()), weak)

    def test_connection_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # 端口现在没人监听
        r = t.check_host("127.0.0.1", port, timeout=2)
        self.assertTrue(r["error"])

    def test_cli_exit_code_and_json(self):
        srv = self.server()
        import io
        import contextlib
        import json
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = t.main([f"127.0.0.1:{srv.port}", "--cafile", self.ca,
                           "--no-probe", "--json"])
        self.assertEqual(code, 1)  # 20 天到期 → 警告
        data = json.loads(buf.getvalue())
        self.assertEqual(data[0]["findings"][0]["level"], "warning")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(t.main([f"127.0.0.1:{srv.port}", "--cafile", self.ca,
                                     "--no-probe", "--warn-days", "10"]), 0)


class TestCli(unittest.TestCase):
    def test_no_targets(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(t.main([]), 2)
            self.assertEqual(t.main(["example.com:abc"]), 2)


if __name__ == "__main__":
    unittest.main()
