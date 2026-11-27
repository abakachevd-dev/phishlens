import os, unittest
import phishlens as p

class SampleTests(unittest.TestCase):
    def test_phishing_samples_score_high(self):
        d = os.path.join(os.path.dirname(__file__), "samples")
        for fn in sorted(os.listdir(d)):
            if fn.startswith("phish_"):
                with open(os.path.join(d, fn), "rb") as fh:
                    self.assertGreaterEqual(p.analyze(fh.read())["score"], 70, fn)

if __name__ == "__main__":
    unittest.main()
