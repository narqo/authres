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
				Version: "1",
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
	}

	for n, tc := range parseTests {
		p := authresParser{tc.in}
		res, _ := p.ParseAuthenticationResults()
		t.Logf("test %d: authres: %#v", n, res)
	}
}