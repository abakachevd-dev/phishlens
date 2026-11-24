import os, unittest
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

if __name__ == "__main__":
    unittest.main()
