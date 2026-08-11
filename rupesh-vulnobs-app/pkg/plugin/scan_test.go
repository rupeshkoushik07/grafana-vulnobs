package plugin

import "testing"

func TestParsePurl(t *testing.T) {
	cases := []struct {
		purl, eco, name, ver string
		ok                   bool
	}{
		{"pkg:npm/lodash@4.17.15", "npm", "lodash", "4.17.15", true},
		{"pkg:npm/%40angular/core@12.0.0", "npm", "@angular/core", "12.0.0", true},
		{"pkg:golang/github.com/gin-gonic/gin@v1.6.0", "Go", "github.com/gin-gonic/gin", "v1.6.0", true},
		{"pkg:pypi/django@1.11", "PyPI", "django", "1.11", true},
		{"pkg:maven/org.apache.commons/commons-lang3@3.9", "Maven", "org.apache.commons:commons-lang3", "3.9", true},
		{"pkg:deb/debian/bash@5.0?distro=debian-11", "Debian:11", "bash", "5.0", true},
		{"pkg:apk/alpine/openssl@1.1?distro=alpine-3.18.4", "Alpine:v3.18", "openssl", "1.1", true},
		{"pkg:rpm/redhat/glibc@2.28", "", "", "", false},
	}
	for _, c := range cases {
		p, ok := parsePurl(c.purl)
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.purl, ok, c.ok)
			continue
		}
		if ok && (p.Ecosystem != c.eco || p.Name != c.name || p.Version != c.ver) {
			t.Errorf("%s -> {%s %s %s}, want {%s %s %s}", c.purl, p.Ecosystem, p.Name, p.Version, c.eco, c.name, c.ver)
		}
	}
}
