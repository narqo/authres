package authres

import "testing"

func TestParseAuthenticationResults(t *testing.T) {
	parseTests := []struct{
		in string
		authres AuthenticationResults
	}{
		{
			`test.example.org 1; none`,
			AuthenticationResults{
				AuthServID: "example.com",
				Version:    "1",
			},
		},
		{
			`example.com; spf=pass smtp.mailfrom=example.net`,
			AuthenticationResults{
				AuthServID: "example.com",
			},
		},
		{
			`example.com; dkim=pass (good signature) header.d=mail-router.example.net; dkim=fail (bad signature) header.d=newyork.example.com`,
			AuthenticationResults{},
		},
		{
			`foo.example.net (foobar) 1 (baz); dkim (Because I like it) / 1 (One yay) = (wait for it) fail policy (A dot can go here) . (like that) expired (this surprised me) = (as I wasn't expecting it) 1362471462`,
			AuthenticationResults{},
		},
	}

	for n, tc := range parseTests {
		p := authresParser{tc.in}
		res, _ := p.ParseAuthenticationResults()
		t.Logf("test %d: authres: %#v", n, res)
	}
}
