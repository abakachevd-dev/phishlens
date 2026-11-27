import base64, os, unittest
from email.message import EmailMessage
import phishlens as p

def load(name):
    with open(os.path.join(os.path.dirname(__file__), "samples", name), "rb") as fh:
        return p.analyze(fh.read())

class PhishLensTests(unittest.TestCase):
    def test_phish_scores_high(self):
        self.assertGreaterEqual(load("phish_paypal.eml")["score"], 70)

    def test_legit_scores_low(self):
        self.assertLessEqual(load("legit_newsletter.eml")["score"], 10)

    def test_lookalike(self):
        self.assertEqual(p.lookalike("paypa1.com")[0], "paypal")
        self.assertIsNone(p.lookalike("paypal.com"))
        self.assertIsNone(p.lookalike("mail.google.com"))

    def test_double_extension(self):
        m = EmailMessage(); m["From"] = "a@b.com"; m.set_content("hi")
        m.add_attachment(b"x", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
        titles = [f["title"] for f in p.analyze(m.as_bytes())["findings"]]
        self.assertIn("Double file extension", titles)

    def test_unwrap_urlencoded(self):
        self.assertEqual(p.unwrap("https://links.example.com/CL0/https:%2F%2Fwww.irs.gov%2Fnews/1/abc"), "www.irs.gov")

    def test_unwrap_base64(self):
        tok = base64.urlsafe_b64encode(b"https://materials.proxyvote.com/a/b?x=1").decode().rstrip("=")
        self.assertEqual(p.unwrap(f"https://track.example.com/f/RgRs0DtuP0RJ{tok}~~"), "materials.proxyvote.com")

    def test_footer_boilerplate_not_flagged(self):
        m = EmailMessage(); m["From"] = "News <a@b.com>"
        m["Authentication-Results"] = "mx; spf=pass; dkim=pass; dmarc=pass"
        m.set_content("Modify your password or log in to manage your subscription.")
        self.assertNotIn("Credential-harvesting language", [f["title"] for f in p.analyze(m.as_bytes())["findings"]])

    def test_empty_and_mailto_links_ignored(self):
        m = EmailMessage(); m.set_content("hi")
        m.add_alternative("<a href=''>x</a><a href='mailto:a@b.com'>y</a>", subtype="html")
        self.assertEqual(p.analyze(m.as_bytes())["links"], [])

    def test_irs_via_platform_only_when_authenticated(self):
        def run(auth):
            m = EmailMessage(); m["From"] = '"Internal Revenue Service" <irs@service.govdelivery.com>'
            if auth: m["Authentication-Results"] = "mx; spf=pass; dkim=pass; dmarc=pass"
            m.set_content("hello")
            return [f["title"] for f in p.analyze(m.as_bytes())["findings"]]
        self.assertNotIn("Display name impersonates a brand", run(True))
        self.assertIn("Display name impersonates a brand", run(False))

if __name__ == "__main__":
    unittest.main()
