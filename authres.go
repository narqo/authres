package authres

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"unicode/utf8"
)

var _ = log.Logger{}

const (
	tokenNone   = "none"
	tokenReason = "reason"
)

type AuthenticationResult struct {
	Method        string
	Version       string
	Result        string
	ResultComment string
	Reason        string
	ReasonComment string
	Properties    []Property
}

type Property struct {
	Type  string
	Name  string
	Value string
}

func (p Property) String() string {
	return p.Type + "." + p.Name + "=" + p.Value
}

var NonAuthenticationResult AuthenticationResult

type AuthenticationResults struct {
	AuthServID string
	Version    string
	Results    []AuthenticationResult
}

type authresParser struct {
	s string
}

func ParseAuthenticationResults(s string) (*AuthenticationResults, error) {
	a := authresParser{s}
	return a.ParseAuthenticationResults()
}

func (p *authresParser) ParseAuthenticationResults() (*AuthenticationResults, error) {
	authServID, err := p.parseAuthServID()
	if err != nil {
		return nil, errors.New("no authserv-id")
	}
	p.skipCFWS()

	version := p.parseVersion()
	if version != "" && version != "1" {
		return nil, fmt.Errorf("unsupported version: %q", version)
	}
	p.skipCFWS()

	authres := &AuthenticationResults{
		AuthServID: authServID,
		Version:    version,
	}

	for {
		res, err := p.parseResinfo()
		if err != nil {
			return nil, err
		}
		//log.Printf("for %q %q %v\n", res, p.s, err)
		if res.Method == "" { // TODO(varankinv): check NonAuthenticationResult
			break
		}
		authres.Results = append(authres.Results, res)
	}

	p.skipCFWS()
	err = p.parseEnd()

	return authres, err
}

func (p *authresParser) parseAuthServID() (string, error) {
	return p.consumeAtom(true, false)
}

func (p *authresParser) parseVersion() (v string) {
	//log.Printf("parseVersion: %q\n", p.s)
	i := 0
	for i <= len(p.s) && isDigit(p.s[i]) {
		i++
	}
	v, p.s = p.s[:i], p.s[i:]
	p.skipCFWS()
	return
}

func (p *authresParser) parseResinfo() (res AuthenticationResult, err error) {
	//log.Printf("parseResinfo %q\n", p.s)
	p.skipCFWS()
	if !p.consume(';') {
		return
	}
	p.skipCFWS()

	if p.consumeToken(tokenNone) {
		return NonAuthenticationResult, nil
	}
	method, version, result, err := p.parseMethodSpec()
	if err != nil {
		return res, err
	}
	p.skipCFWS()
	reason, err := p.parseReasonSpec()
	if err != nil {
		return res, err
	}

	res.Method = method
	res.Version = version
	res.Result = result
	res.Reason = reason

	for {
		p.skipCFWS()
		ptype, prop, val, err := p.parsePropSpec()
		if err != nil {
			return res, err
		}
		if ptype == "" {
			break
		}

		res.Properties = append(res.Properties, Property{ptype, prop, val})
	}

	//log.Printf("method %q, version %q, result %q, reason %q, ps %q\n", method, version, result, reason, p.s)

	return
}

func (p *authresParser) parseMethodSpec() (method, version, result string, err error) {
	p.skipCFWS()
	method, version, err = p.parseMethod()
	//log.Printf("parse method %q %q %q %v\n", method, version, p.s, err)
	if err != nil {
		return
	}
	p.skipCFWS()
	if !p.consume('=') {
		err = errors.New("method-spec: expected \"=\"")
		return
	}
	p.skipCFWS()
	result, err = p.consumeAtom(true, false)
	if err != nil {
		return
	}
	if result == "" {
		err = errors.New("method-spec: expected result")
		return
	}
	return
}

func (p *authresParser) parseMethod() (method, version string, err error) {
	//method, err = p.consumeAtom(true, false)
	method, err = p.consumeAnyText(func(r rune) bool {
		if r == '=' {
			return false
		}
		return isAtext(r, true)
	})
	if err != nil {
		return
	}
	if method == "" {
		return "", "", errors.New("expected method")
	}
	p.skipCFWS()
	if !p.consume('/') {
		return
	}
	p.skipCFWS()
	version = p.parseVersion()
	return
}

func (p *authresParser) parseReasonSpec() (reason string, err error) {
	//log.Printf("parse reason spec %q %v\n", p.s, err)
	if p.consumeToken(tokenReason) {
		p.skipCFWS()
		if !p.consume('=') {
			return "", errors.New("reason-spec: expected \"=\"")
		}
		p.skipCFWS()

		quoted, err := p.consumeQuotedString()
		if err != nil {
			return "", err
		}
		if len(quoted) > 0 {
			reason = quoted
		} else {
			reason, err = p.consumeAtom(true, false)
		}

	}
	return
}

func (p *authresParser) parsePropSpec() (ptype, prop, val string, err error) {
	ptype, err = p.consumeAtom(false, false)
	//log.Printf("parse prop spec %q %q %v\n", ptype, p.s, err)
	if err != nil {
		err = nil // ignore this error
		return
	}
	switch strings.ToLower(ptype) {
	case "":
		return
	case "smtp", "header", "body", "policy", "mailfrom":
	default:
		return "", "", "", fmt.Errorf("prop-spec: invalid ptype: %q", ptype)
	}
	p.skipCFWS()

	if !p.consume('.') {
		return "", "", "", errors.New("prop-spec: expected \".\"")
	}
	p.skipCFWS()

	prop, err = p.consumeAnyText(func(r rune) bool {
		if r == '=' {
			return false
		}
		return isAtext(r, true)
	})
	if err != nil {
		return
	}
	p.skipCFWS()
	if !p.consume('=') {
		return "", "", "", errors.New("prop-spec: expected \"=\"")
	}
	val, err = p.parsePValue()
	if err != nil {
		return
	}
	if val == "" {
		return "", "", "", errors.New("prop-spec: expected pvalue")
	}
	return
}

func (p *authresParser) parsePValue() (string, error) {
	p.skipCFWS()
	quoted, err := p.consumeQuotedString()
	if err != nil {
		return "", err
	}
	if len(quoted) > 0 {
		if p.consume('@') {
			// parse quoted-string "@" domain-name
			domain, err := p.consumeAtom(true, false)
			if err != nil {
				return "", err
			}
			p.skipCFWS()
			if domain != "" {
				return quoted + "@" + domain, nil
			}
		} else {
			p.skipCFWS()
			return quoted, nil
		}
	} else {
		if p.consume('@') {
			// parse "@" domain-name
			domain, err := p.consumeAtom(true, false)
			if err != nil {
				return "", err
			}
			p.skipCFWS()
			if domain != "" {
				return "@" + domain, nil
			}
		} else {
			// parse *ptext
			pvalue, err := p.consumeAnyText(func(r rune) bool {
				if r == '=' {
					return false
				}
				return isAtext(r, true)
			})
			if err != nil {
				return "", err
			}
			p.skipCFWS()
			if pvalue != "" {
				return pvalue, nil
			}
		}
	}
	return "", nil
}

func (p *authresParser) parseEnd() error {
	if !p.empty() {
		return fmt.Errorf("expected end of test: %q", p.s)
	}
	return nil
}

func (p *authresParser) consumeQuotedString() (string, error) {
	if p.consume('"') {
		var result []string
		for !p.consume('"') {
			t, err := p.consumeAtom(true, false)
			if len(t) > 0 {
				result = append(result, t)
			}
			if err != nil {
				return "", err
			}
			p.skipCFWS()
		}
		return strings.Join(result, " "), nil
	}
	return "", nil
}

func (p *authresParser) consumeAtom(dot bool, permissive bool) (atom string, err error) {
	i := 0

Loop:
	for {
		r, size := utf8.DecodeRuneInString(p.s[i:])

		switch {
		case size == 1 && r == utf8.RuneError:
			return "", fmt.Errorf("invalid utf-8 in address: %q", p.s)

		case size == 0 || !isAtext(r, dot):
			break Loop

		default:
			i += size

		}
	}

	if i == 0 {
		return "", errors.New("invalid string")
	}
	atom, p.s = p.s[:i], p.s[i:]
	if !permissive {
		if strings.HasPrefix(atom, ".") {
			return "", errors.New("leading dot in atom")
		}
		if strings.Contains(atom, "..") {
			return "", errors.New("double dot in atom")
		}
		if strings.HasSuffix(atom, ".") {
			return "", errors.New("trailing dot in atom")
		}
	}
	return atom, nil
}

func (p *authresParser) consumeAnyText(checkFn func(c rune) bool) (anytext string, err error) {
	if p.empty() {
		return
	}
	i := 0
	for i < len(p.s) && checkFn(rune(p.s[i])) {
		i++
	}
	if i == 0 {
		return "", errors.New("invalid string")
	}
	anytext, p.s = p.s[:i], p.s[i:]
	return anytext, nil
}

func (p *authresParser) consumeToken(t string) bool {
	if len(p.s) >= len(t) && p.s[:len(t)] == t {
		p.s = p.s[len(t):]
		return true
	}
	return false
}

func (p *authresParser) consume(c byte) bool {
	if p.empty() || p.peek() != c {
		return false
	}
	p.s = p.s[1:]
	return true
}

func (p *authresParser) peek() byte {
	return p.s[0]
}

func (p *authresParser) skipCFWS() {
	p.skipSpace()
	//log.Printf("skipCFWS: %q\n", p.s)
	for p.skipComment() {
		p.skipSpace()
	}
	p.skipSpace()
}

func (p *authresParser) skipSpace() {
	p.s = strings.TrimLeft(p.s, " \t")
}

func (p *authresParser) skipComment() bool {
	if p.consume('(') {
		p.skipSpace()
		for !p.consume(')') {
			p.skipCContent()
		}
		if !p.consume(')') {
			return false
		}
		return true
	}
	return false
}

func (p *authresParser) skipCContent() {
	i := 0
	for {
		r, size := utf8.DecodeRuneInString(p.s[i:])
		//log.Printf("skip %q %d %q\n", r, size, p.s)
		if size == 1 && r == utf8.RuneError {
			return
		}
		if size == 0 || !isCchar(r) {
			break
		}
		i += size
	}
	if i > 0 {
		p.s = p.s[i:]
	}
	p.skipSpace()
	p.skipComment()
	return
}

func (p *authresParser) empty() bool {
	return len(p.s) == 0
}

// isDigit reports whether c is digit.
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// isAtext reports whether r is an RFC 5322 atext character.
// If dot is true, period is included.
func isAtext(r rune, dot bool) bool {
	switch r {
	case '.':
		return dot

	case '(', ')', '<', '>', '[', ']', ':', ';', '@', '\\', ',', '"': // RFC 5322 3.2.3. specials
		return false
	}
	return isVchar(r)
}

// isQtext reports whether r is an RFC 5322 qtext character.
func isQtext(r rune) bool {
	// Printable US-ASCII, excluding backslash or quote.
	if r == '\\' || r == '"' {
		return false
	}
	return isVchar(r)
}

// isCchar reports whether r is a RFC 5322 cchar character.
func isCchar(r rune) bool {
	if r == '(' || r == ')' || r == '\\' {
		return false
	}
	return isVchar(r)
}

// isVchar reports whether r is an RFC 5322 VCHAR character.
func isVchar(r rune) bool {
	// Visible (printing) characters.
	return '!' <= r && r <= '~' || isMultibyte(r)
}

// isMultibyte reports whether r is a multi-byte UTF-8 character
// as supported by RFC 6532
func isMultibyte(r rune) bool {
	return r >= utf8.RuneSelf
}

// isWSP reports whether r is a WSP (white space).
// WSP is a space or horizontal tab (RFC 5234 Appendix B).
func isWSP(r rune) bool {
	return r == ' ' || r == '\t'
}
