package roundrobin

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// StickySession is a mixin for load balancers that implements layer 7 (http cookie) session affinity
type StickySession struct {
	cookieName   string
	cookieSecret string
}

// NewStickySession creates a new StickySession
func NewStickySession(cookieName string, cookieSecret string) *StickySession {
	return &StickySession{cookieName: cookieName, cookieSecret: cookieSecret}
}

// GetBackend returns the backend URL stored in the sticky cookie, if the backend is still in the valid list of servers.
func (s *StickySession) GetBackend(req *http.Request, servers []*url.URL) (*url.URL, bool, error) {
	cookie, err := req.Cookie(s.cookieName)
	switch err {
	case nil:
	case http.ErrNoCookie:
		return nil, false, nil
	default:
		return nil, false, err
	}

	hash := hmac.New(sha256.New, []byte(s.cookieSecret))
	var theServer *url.URL
	for _, serverURL := range servers {
		hash.Reset()
		io.WriteString(hash, serverURL.String())
		if fmt.Sprintf("%x", hash.Sum(nil)) == cookie.Value {
			theServer = serverURL
			break
		}
	}
	if theServer == nil {
		return nil, false, nil
	}

	if s.isBackendAlive(theServer, servers) {
		return theServer, true, nil
	}
	return nil, false, nil
}

// StickBackend creates and sets the cookie
func (s *StickySession) StickBackend(backend *url.URL, w *http.ResponseWriter) {
	hash := hmac.New(sha256.New, []byte(s.cookieSecret))
	io.WriteString(hash, backend.String())
	cookie := &http.Cookie{Name: s.cookieName, Value: fmt.Sprintf("%x", hash.Sum(nil)), Path: "/"}
	http.SetCookie(*w, cookie)
}

func (s *StickySession) isBackendAlive(needle *url.URL, haystack []*url.URL) bool {
	if len(haystack) == 0 {
		return false
	}

	for _, serverURL := range haystack {
		if sameURL(needle, serverURL) {
			return true
		}
	}
	return false
}
