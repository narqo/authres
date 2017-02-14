package authres

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const eof byte = iota

type AuthenticationResults struct {
	AuthServID string
	Version    string
}

type authresParser struct {
	s string
}

func (p *authresParser) ParseAuthenticationResults() (*AuthenticationResults, error) {
	authServID, err := p.parseAuthServID()
	if err != nil {
		return nil, errors.New("no authserv-id")
	}
	p.skipSpace()

	version := p.parseVersion()
	if version != "" && version != "1" {
		return nil, fmt.Errorf("unsupported version: %q", version)
	}
	p.skipSpace()

	return &AuthenticationResults{
		AuthServID: authServID,
		Version:    version,
	}, nil
}

func (p *authresParser) parseAuthServID() (string, error) {
	return p.consumeAtom(true, false)
}

func (p *authresParser) parseVersion() (v string) {
	i := 0
	for ; i < len(p.s) && strings.IndexByte("1234567890", p.s[i]) >= 0; i++ {
	}
	v, p.s = p.s[:i], p.s[i+1:]
	p.skipSpace()
	return
}

func (p *authresParser) parseReginfo() string {
	p.skipSpace()
	if p.consume() != ';' {
		return ""
	}
	p.skipSpace()

	return ""
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

func (p *authresParser) consume() (c byte) {
	if p.empty() {
		return eof
	}
	c, p.s = p.s[0], p.s[1:]
	return
}

func (p *authresParser) peek() byte {
	return p.s[0]
}

func (p *authresParser) skipSpace() {
	p.s = strings.TrimLeft(p.s, " \t")
}

func (p *authresParser) empty() bool {
	return len(p.s) == 0
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

// quoteString renders a string as an RFC 5322 quoted-string.
func quoteString(s string) string {
	var buf bytes.Buffer
	buf.WriteByte('"')
	for _, r := range s {
		if isQtext(r) || isWSP(r) {
			buf.WriteRune(r)
		} else if isVchar(r) {
			buf.WriteByte('\\')
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return buf.String()
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
