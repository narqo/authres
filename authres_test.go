package authres

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseAuthenticationResults(t *testing.T) {
	parseTests := []struct {
		in      string
		authres AuthenticationResults
	}{
		{
			`test.example.org 1; none`,
			AuthenticationResults{
				AuthServID: "test.example.org",
				Version:    "1",
			},
		},
		{
			`example.com; spf=pass smtp.mailfrom=example.net`,
			AuthenticationResults{
				AuthServID: "example.com",
				Results: []AuthenticationResult{
					{
						Method:     "spf",
						Result:     "pass",
						Properties: []string{"smtp+++mailfrom+++example.net"},
					},
				},
			},
		},
		{
			`example.com; dkim=pass (good signature) header.d=mail-router.example.net; dkim=fail (bad signature) header.d=newyork.example.com`,
			AuthenticationResults{
				AuthServID: "example.com",
				Results: []AuthenticationResult{
					{
						Method:     "dkim",
						Result:     "pass",
						Properties: []string{"header+++d+++mail-router.example.net"},
					},
					{
						Method:     "dkim",
						Result:     "fail",
						Properties: []string{"header+++d+++newyork.example.com"},
					},
				},
			},
		},
		{
			`foo.example.net (foobar) 1 (baz); dkim (Because I like it) /1 (One yay) = (wait for it) fail policy (A dot can go here) . (like that) expired (this surprised me) = (as I wasn't expecting it) 1362471462`,
			AuthenticationResults{
				AuthServID: "foo.example.net",
				Version:    "1",
				Results: []AuthenticationResult{
					{
						Method:     "dkim",
						Version:    "1",
						Result:     "fail",
						Properties: []string{"policy+++expired+++1362471462"},
					},
				},
			},
		},
	}

	for n, tc := range parseTests {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			res, err := ParseAuthenticationResults(tc.in)
			if err != nil {
				t.Errorf("test %d: error: %v", n, err)
			}
			if !reflect.DeepEqual(*res, tc.authres) {
				t.Errorf("want: %+v, got: %+v", tc.authres, *res)
			}
		})
	}
}
