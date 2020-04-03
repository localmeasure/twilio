# twilio
golang twilio utils

## signature
```
import "github.com/localmeasure/twilio/signature"

...

passed, err := signature.Validate(r, "http://example.com/foo?bar=1", []byte("secret"))
```
