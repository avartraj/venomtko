#!/usr/bin/env python3
"""
Offline logic tests for VenomTKO — no network, no DNS, no external tools.

Covers the pure functions that drive detection accuracy: input normalisation,
mode detection, the unified hostname extractor, fingerprint normalisation,
candidate filtering, and the confidence/classification model (including the new
SERVFAIL dangling signal and nxdomain-only services).

Run with:  python test_venomtko.py      (stdlib unittest, no pytest needed)
"""

from __future__ import annotations

import unittest

import venomtko as st


class TestNormalisation(unittest.TestCase):
    def test_to_host_strips_scheme_path_and_wildcard(self):
        self.assertEqual(st.to_host("https://Foo.Example.com/path?x=1"), "foo.example.com")
        self.assertEqual(st.to_host("*.example.com"), "example.com")
        self.assertEqual(st.to_host("sub.example.com/page"), "sub.example.com")
        self.assertEqual(st.to_host("HTTP://Host.EXAMPLE.com"), "host.example.com")

    def test_detect_mode(self):
        urls = ["https://a.com", "http://b.com", "x.com"]
        domains = ["a.com", "b.com", "c.com"]
        self.assertEqual(st.detect_mode(urls, "auto"), "urls")
        self.assertEqual(st.detect_mode(domains, "auto"), "domains")
        self.assertEqual(st.detect_mode(domains, "urls"), "urls")  # forced wins


class TestExtractor(unittest.TestCase):
    def test_pulls_and_normalises_hosts(self):
        extract = st.make_extractor("example.com")
        text = (
            'crt: "a.example.com"\\n'        # literal escaped newline must not fuse
            'b.example.com,*.c.example.com\n'
            'https://d.example.com/x not-example.org other.com'
        )
        got = extract(text)
        self.assertIn("a.example.com", got)
        self.assertIn("b.example.com", got)
        self.assertIn("c.example.com", got)   # leading *. stripped
        self.assertIn("d.example.com", got)
        self.assertNotIn("not-example.org", got)
        self.assertNotIn("other.com", got)
        # the escaped-newline split must not produce a fused 'na.example.com'
        self.assertFalse(any(h.startswith("n") and "a.example.com" in h for h in got
                             if h != "a.example.com"))


class TestFingerprintLoading(unittest.TestCase):
    def test_normalise_handles_string_and_list_and_bools(self):
        raw = [
            {"service": "S3", "cname": "amazonaws.com",
             "fingerprint": "NoSuchBucket", "vulnerable": "true", "nxdomain": "false"},
            {"service": "AzureNX", "cname": ["azurefd.net"],
             "fingerprint": "", "vulnerable": True, "nxdomain": True},
        ]
        out = st.normalise_fingerprints(raw)
        self.assertEqual(out[0]["cname"], ["amazonaws.com"])
        self.assertEqual(out[0]["fingerprint"], ["nosuchbucket"])  # lowercased
        self.assertTrue(out[0]["vulnerable"])
        self.assertFalse(out[0]["nxdomain"])
        self.assertTrue(out[1]["nxdomain"])
        self.assertEqual(out[1]["fingerprint"], [])

    def test_default_fingerprints_are_well_formed(self):
        fps = st.normalise_fingerprints(st.DEFAULT_FINGERPRINTS)
        self.assertTrue(fps)
        for fp in fps:
            self.assertIn("service", fp)
            self.assertIsInstance(fp["cname"], list)
            self.assertIsInstance(fp["fingerprint"], list)
            self.assertIsInstance(fp["vulnerable"], bool)
            self.assertIsInstance(fp["nxdomain"], bool)


class TestCandidateFilter(unittest.TestCase):
    def setUp(self):
        # Pin to the built-in defaults so tests are hermetic (independent of any
        # community DB the user may have cached via --update-fingerprints).
        self.fps = st.normalise_fingerprints(st.DEFAULT_FINGERPRINTS)

    def test_no_cname_is_never_candidate(self):
        r = st.HostResult(host="x", status=404)
        self.assertFalse(st.is_candidate(r, self.fps))

    def test_dangling_cname_is_candidate(self):
        r = st.HostResult(host="x", cname_chain=["foo.s3.amazonaws.com"],
                          nxdomain_target=True)
        self.assertTrue(st.is_candidate(r, self.fps))

    def test_servfail_cname_is_candidate(self):
        r = st.HostResult(host="x", cname_chain=["foo.azurefd.net"],
                          servfail_target=True)
        self.assertTrue(st.is_candidate(r, self.fps))

    def test_error_status_with_cname_is_candidate(self):
        r = st.HostResult(host="x", cname_chain=["foo.github.io"], status=404)
        self.assertTrue(st.is_candidate(r, self.fps))

    def test_known_service_cname_on_200_is_candidate(self):
        # resolving 200 but CNAME points at a fingerprinted service -> still worth it
        r = st.HostResult(host="x", cname_chain=["foo.myshopify.com"],
                          status=200, resolved=True)
        self.assertTrue(st.is_candidate(r, self.fps))

    def test_healthy_unknown_200_dropped(self):
        r = st.HostResult(host="x", cname_chain=["edge.unknown-cdn.net"],
                          status=200, resolved=True)
        self.assertFalse(st.is_candidate(r, self.fps))


class TestClassification(unittest.TestCase):
    def setUp(self):
        # Pin to the built-in defaults so tests are hermetic (independent of any
        # community DB the user may have cached via --update-fingerprints).
        self.fps = st.normalise_fingerprints(st.DEFAULT_FINGERPRINTS)

    def test_high_cname_plus_body(self):
        r = st.HostResult(host="x", cname_chain=["foo.github.io"], status=404)
        st.classify(r, "There isn't a GitHub Pages site here", self.fps)
        self.assertEqual(r.confidence, "high")
        self.assertTrue(r.vulnerable)
        self.assertIn("cname", r.matched_on)
        self.assertIn("body", r.matched_on)

    def test_high_cname_plus_nxdomain(self):
        r = st.HostResult(host="x", cname_chain=["foo.s3.amazonaws.com"],
                          nxdomain_target=True)
        st.classify(r, "", self.fps)
        self.assertEqual(r.confidence, "high")
        self.assertIn("dangling-cname", r.matched_on)

    def test_high_via_servfail_dangling(self):
        r = st.HostResult(host="x", cname_chain=["foo.herokuapp.com"],
                          servfail_target=True)
        st.classify(r, "", self.fps)
        self.assertEqual(r.confidence, "high")

    def test_live_vulnerable_service_no_corroboration_is_suppressed(self):
        # CNAME to a vulnerable service, but live and serving normal content
        # (no body fingerprint, not dangling) -> NOT a takeover -> suppressed.
        r = st.HostResult(host="x", cname_chain=["foo.herokuapp.com"], status=404)
        st.classify(r, "totally unrelated body", self.fps)
        self.assertEqual(r.confidence, "none")

    def test_medium_offdomain_dangling(self):
        # Dangling CNAME whose target leaves the host's apex -> claimable -> medium.
        r = st.HostResult(host="sub.victim.com",
                          cname_chain=["foo.unknown-thirdparty.net"],
                          nxdomain_target=True)
        st.classify(r, "", self.fps)
        self.assertEqual(r.confidence, "medium")
        self.assertIn("dangling-cname", r.matched_on)

    def test_same_org_dangling_is_suppressed(self):
        # Dangling CNAME to the host's OWN registrable domain -> internal DNS
        # hygiene, not externally exploitable -> suppressed.
        r = st.HostResult(host="bouncer.sec.gitlab.net",
                          cname_chain=["dead.trust-safety.sec.gitlab.net"],
                          nxdomain_target=True)
        st.classify(r, "", self.fps)
        self.assertEqual(r.confidence, "none")

    def test_body_fp_with_mismatched_cname_is_suppressed(self):
        # The real GitLab false positive: CNAME points at a non-fingerprinted
        # service (mailgun) but the body happens to contain another service's
        # generic fingerprint string. Must NOT be flagged.
        r = st.HostResult(host="email.mg.example.org", cname_chain=["mailgun.org"],
                          status=404, resolved=True)
        st.classify(r, "There isn't a GitHub Pages site here", self.fps)
        self.assertEqual(r.confidence, "none")
        self.assertFalse(r.vulnerable)

    def test_non_vulnerable_service_is_suppressed(self):
        # Netlify is flagged non-vulnerable in the default set -> never a finding.
        r = st.HostResult(host="x.victim.com", cname_chain=["foo.netlify.app"],
                          nxdomain_target=True, status=404)
        st.classify(r, "Not Found - Request ID: abc", self.fps)
        self.assertEqual(r.confidence, "none")
        self.assertFalse(r.vulnerable)


class TestVerifierResolution(unittest.TestCase):
    def test_none_spec(self):
        self.assertEqual(st.resolve_verifiers(None), [])

    def test_unknown_names_filtered(self):
        # 'foo' is not a known verifier; result only ever contains installed tools.
        out = st.resolve_verifiers("foo")
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
