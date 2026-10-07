"""Meaningful offline safety checks; does not simulate a real OS kill switch."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/owned-vps-egress/scripts"))
import prepare
import publish_check
import validate
import yaml


class KitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="owned-egress-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def args(self, name="first", **overrides):
        values = dict(recipient=name, new_vps_ip="192.0.2.10", sni="example.com",
                      port=9443, clients=2, platform=["windows", "macos", "linux"],
                      direct_domain=[], allow_lan=False, qr=False, test_fixture=True,
                      output=str(self.base / name))
        values.update(overrides)
        return argparse.Namespace(**values)

    def generate(self, **kwargs):
        options = self.args(**kwargs)
        prepare.create(options)
        return Path(options.output)

    def test_cross_platform_cross_file_validation(self):
        folder = self.generate(qr=True)
        result = validate.validate(folder)
        self.assertEqual(result["offline_validation"], "passed")
        self.assertEqual(result["clients"], 2)
        self.assertTrue((folder / "clients/client01/shadowrocket-node.private.png").is_file())

    def test_recipients_have_independent_keys_and_uuids(self):
        a, b = self.generate(name="a"), self.generate(name="b")
        def inbound(folder):
            return json.loads((folder / "server/server.private.json").read_text())["inbounds"][0]
        x, y = inbound(a), inbound(b)
        self.assertNotEqual(x["tls"]["reality"]["private_key"], y["tls"]["reality"]["private_key"])
        self.assertFalse({u["uuid"] for u in x["users"]} & {u["uuid"] for u in y["users"]})

    def test_existing_output_is_not_overwritten(self):
        self.generate()
        with self.assertRaises(FileExistsError):
            prepare.create(self.args())

    def test_no_private_output_inside_public_repo(self):
        with self.assertRaises(ValueError):
            prepare.create(self.args(output=str(ROOT / "generated")))

    def test_fixture_never_targets_real_network(self):
        with self.assertRaises(ValueError):
            prepare.create(self.args(new_vps_ip="1.1.1.1"))

    def test_real_recipe_rejects_loopback(self):
        with self.assertRaises(ValueError):
            prepare.create(self.args(new_vps_ip="127.0.0.1", test_fixture=False))

    def test_direct_exception_cannot_override_protected_domain(self):
        for d in ("openai.com", "api.openai.com", "com"):
            with self.subTest(domain=d), self.assertRaises(ValueError):
                prepare.create(self.args(direct_domain=[d]))

    def test_lan_and_domain_exceptions_are_explicit(self):
        folder = self.generate(allow_lan=True, direct_domain=["example.org"])
        validate.validate(folder)
        c = yaml.safe_load((folder / "clients/client01/mihomo-windows.private.yaml").read_text())
        self.assertIn("DOMAIN-SUFFIX,example.org,DIRECT", c["rules"])
        self.assertIn("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", c["rules"])
        self.assertEqual(c["rules"][-1], "MATCH,PROXY")
        self.assertTrue(all(x.endswith("#PROXY") for x in c["dns"]["nameserver"]))

    def test_foreign_exit_detected_even_after_hash_updated(self):
        folder = self.generate()
        path = folder / "clients/client01/mihomo-windows.private.yaml"
        c = yaml.safe_load(path.read_text())
        c["proxies"][0]["server"] = "192.0.2.11"
        path.write_text(yaml.safe_dump(c), encoding="utf-8")
        manifest_path = folder / "manifest.private.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"][str(path.relative_to(folder)).replace("\\", "/")] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Foreign exit"):
            validate.validate(folder)

    def test_modified_artifact_fails_hash_check(self):
        folder = self.generate()
        p = folder / "clients/client01/shadowrocket-node.private.txt"
        p.write_text(p.read_text() + "tampered", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            validate.validate(folder)

    def test_guard_rejects_bad_identity_capture_and_bypass(self):
        folder = self.generate()
        c = yaml.safe_load((folder / "clients/client01/mihomo-windows.private.yaml").read_text())
        cases = []
        for mutate in (lambda x: x["proxies"][0].update(server="192.0.2.11"),
                       lambda x: x["tun"].update(enable=False),
                       lambda x: x["tun"].update({"dns-hijack": ["any:53"]}),
                       lambda x: x["tun"].update({"exclude-interface": ["eth0"]}),
                       lambda x: x.update(ipv6=False),
                       lambda x: x["proxies"][0].update({"dialer-proxy": "SUPPLIER"})):
            candidate = copy.deepcopy(c)
            mutate(candidate)
            cases.append(candidate)
        js = prepare.guard(c) + "\nconst cases = " + json.dumps(cases) + ";\n" + """
const assert = require('node:assert/strict');
for (const candidate of cases) {
  const r = main(candidate);
  assert.deepEqual(r.rules, ['MATCH,REJECT']);
  assert.deepEqual(r['proxy-groups'][1].proxies, ['REJECT']);
  assert.equal(r.proxies.length, 0);
}
const good = JSON.parse(JSON.stringify(approved));
good['proxy-providers'] = {untrusted: {type:'http', url:'https://example.com'}};
good.rules = ['MATCH,DIRECT'];
good['proxy-groups'][1].proxies.push('DIRECT');
const result = main(good);
assert.deepEqual(result.rules, approved.rules);
assert.deepEqual(result['proxy-groups'], approved['proxy-groups']);
assert.deepEqual(result['proxy-providers'], {});
console.log('GUARD_BEHAVIOR_PASS');
"""
        path = self.base / "guard-test.cjs"
        path.write_text(js, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, "Node guard behavioral test failed; inspect private fixture")
        self.assertIn("GUARD_BEHAVIOR_PASS", result.stdout)

    def test_publisher_rejects_realistic_credential_and_artifact(self):
        folder = self.base / "publish"
        folder.mkdir()
        # Generate a dummy credential rather than commit one in this test source.
        import uuid
        (folder / "bad.txt").write_text("vless://" + str(uuid.uuid4()) + "@192.0.2.1:9443")
        (folder / "config.private.yaml").write_text("private")
        problems, _ = publish_check.scan(folder)
        self.assertTrue(any("UUID credential" in x for x in problems))
        self.assertTrue(any("private/binary artifact" in x for x in problems))


if __name__ == "__main__":
    unittest.main(verbosity=2)
