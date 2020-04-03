package signature

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	want := "RSOYDt4T1cUTdK1PDd93/VVr8B8="
	turl := "https://mycompany.com/myapp.php?foo=1&bar=2"
	key := []byte("12345")
	data := url.Values{
		"CallSid": []string{"CA1234567890ABCDE"},
		"Caller":  []string{"+14158675309"},
		"Digits":  []string{"1234"},
		"From":    []string{"+14158675309"},
		"To":      []string{"+18005551212"},
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(data.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("x-twilio-signature", want)
	sig, err := Sign(r, turl, key)
	if err != nil {
		t.Errorf("Sign() error = %v", err)
	}
	if sig != want {
		t.Errorf("Sign() = %v, want %v", sig, want)
	}
	passed, err := Validate(r, turl, key)
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
	if !passed {
		t.Errorf("Validate() = %v, want %v", passed, true)
	}
}
