package signature

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"sort"
)

type field struct {
	name   string
	values []string
}

type byName []field

func (a byName) Len() int           { return len(a) }
func (a byName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byName) Less(i, j int) bool { return a[i].name < a[j].name }

// Sign follows https://www.twilio.com/docs/usage/security#validating-requests
func Sign(r *http.Request, url string, key []byte) (sig string, err error) {
	if err = r.ParseForm(); err != nil {
		return
	}
	var fields []field
	for name, values := range r.PostForm {
		fields = append(fields, field{
			name:   name,
			values: values,
		})
	}
	sort.Sort(byName(fields))
	var b bytes.Buffer
	b.WriteString(url)
	for _, f := range fields {
		b.WriteString(f.name)
		if len(f.values) > 0 {
			b.WriteString(f.values[0])
		}
	}
	mac := hmac.New(sha1.New, key)
	if _, err = mac.Write(b.Bytes()); err != nil {
		return
	}
	sig = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return
}

func Validate(r *http.Request, url string, key []byte) (bool, error) {
	sig, err := Sign(r, url, key)
	if err != nil {
		return false, err
	}
	return r.Header.Get("X-Twilio-Signature") == sig, nil
}
