package sbom

import "testing"

func TestSplitRef(t *testing.T) {
	const dig = "sha256:6f5a644135887b2aa7d5cc145072fa56421560e3586ff1f184358022d490f4e1"
	cases := []struct {
		in                        string
		wantRepo, wantTag, wantDg string
	}{
		{"quay.io/jetstack/cainjector:v1.20.2@" + dig, "quay.io/jetstack/cainjector", "v1.20.2", dig},
		{"quay.io/jetstack/cainjector@" + dig, "quay.io/jetstack/cainjector", "", dig},
		{"quay.io/jetstack/cainjector:v1.20.2", "quay.io/jetstack/cainjector", "v1.20.2", ""},
		{"registry:5000/app:1.2", "registry:5000/app", "1.2", ""},
		{"registry:5000/app", "registry:5000/app", "", ""},
		{"alpine", "alpine", "", ""},
		{"alpine:3.19", "alpine", "3.19", ""},
		{"library/alpine@" + dig, "library/alpine", "", dig},
	}
	for _, c := range cases {
		repo, tag, dg := SplitRef(c.in)
		if repo != c.wantRepo || tag != c.wantTag || dg != c.wantDg {
			t.Errorf("SplitRef(%q) = (%q,%q,%q), want (%q,%q,%q)",
				c.in, repo, tag, dg, c.wantRepo, c.wantTag, c.wantDg)
		}
		if got := Repository(c.in); got != c.wantRepo {
			t.Errorf("Repository(%q) = %q, want %q", c.in, got, c.wantRepo)
		}
		if got := Tag(c.in); got != c.wantTag {
			t.Errorf("Tag(%q) = %q, want %q", c.in, got, c.wantTag)
		}
	}
}

func TestAsDigest(t *testing.T) {
	const good = "sha256:6f5a644135887b2aa7d5cc145072fa56421560e3586ff1f184358022d490f4e1"
	if got := asDigest(good); got != good {
		t.Errorf("asDigest(valid) = %q, want %q", got, good)
	}
	for _, bad := range []string{"", "sha256:short", "notadigest", "sha512:" + good[7:]} {
		if got := asDigest(bad); got != "" {
			t.Errorf("asDigest(%q) = %q, want empty", bad, got)
		}
	}
}
