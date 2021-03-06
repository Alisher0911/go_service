package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/ardanlabs/service/business/auth"
	"github.com/dgrijalva/jwt-go"
	"log"
	"testing"
	"time"
)

const (
	success = "\u2713"
	failed = "\u2717"
)

func TestAuth(t *testing.T) {
	t.Log("Given the need to be able to authenticate and authorize access.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen handling a single user.", testID)
		{
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				log.Fatalln(err)
			}

			const keyID = "54bb2165-71e1-41a6-af3e-7da4a0e1e2c1"
			lookup := func(kid string) (*rsa.PublicKey, error) {
				switch kid {
				case keyID:
					return &privateKey.PublicKey, nil
				}
				return nil, fmt.Errorf("no public key found for the specified kid: %s", kid)
			}

			a, err := auth.New("RS256", lookup, auth.Keys{keyID: privateKey})
			if err != nil {
				t.Fatalf("\t%s\tTest %d:\tShould be able to create an authenticator: %v", failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould be able to create an authenticator.", success, testID)

			claims := auth.Claims{
				StandardClaims: jwt.StandardClaims{
					Issuer: 	"service project",
					Subject: 	"5cf37266-3473-4006-984f-9325122678b7",
					Audience: 	"students",
					ExpiresAt: 	time.Now().Add(8760 * time.Hour).Unix(),
					IssuedAt: 	time.Now().Unix(),
				},
				Roles: []string{auth.RoleAdmin},
			}

			token, err := a.GenerateToken(keyID, claims)
			if err != nil {
				t.Fatalf("\t%s\tTest %d:\tShould be able to generate a JWT: %v", failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould be able to generate a JWT.", success, testID)

			parsedClaims, err := a.ValidateToken(token)
			if err != nil {
				t.Fatalf("\t%s\tTest %d:\tShould be able to parse the claims: %v", failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould be able to parse the claims.", success, testID)

			if exp, got := len(claims.Roles), len(parsedClaims.Roles); exp != got {
				t.Logf("\t\tTest %d:\texp: %d", testID, exp)
				t.Logf("\t\tTest %d:\tgot: %d", testID, got)
				t.Fatalf("\t%s\tTest %d:\tShould have the expected number of roles: %v", failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould have the expected number of roles.", success, testID)

			if exp, got := claims.Roles[0], parsedClaims.Roles[0]; exp != got {
				t.Logf("\t\tTest %d:\texp: %v", testID, exp)
				t.Logf("\t\tTest %d:\tgot: %v", testID, got)
				t.Fatalf("\t%s\tTest %d:\tShould have the expected roles: %v", failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould have the expected roles.", success, testID)
		}
	}
}

const privateRSAKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuEO8cCo9UKjhKbp5uzjTSqfWIESYq4GrbGc1VCpBjNAyulAd
VaGsZ3bsq7AU1XEBtYUSfSYgY18WtrI/htkzwm7K5VYIlxLx9tYerGSGN7tUQOFg
vc27HkVAuCRrKwyuTpvYMjP2tRHYtb/GjGvrLjX7bPG8u6hIeT8iW0LgAXhRi6p8
Ef4NjDd1WITzoi9xYRH9+ZBVV3CK4oS7j0Ui9HvGTRsZXj6BuBUJE5s4xpD7vVA3
LubYwaCZox/VF0mkMOuY/RO7azOzrlOOZnEvWti8riOQoZSuraV32EYcZ3aSYNfv
wg14OyGTq6flBjT3vmtpEs6qyopcX8/01u9N6wIDAQABAoIBAFJA8nJDeMFz0ac1
9bcsg61UxJH87QXKSYKHg9fBUSeRnMNslduu4u4AuV9ep74rxu6Hq5wwE88oGFSP
tynz9VX67Rl40TbXHynnpSOhcASa295mfS/dEYVOtrg8kZZS/9BZYyXt6lgj0lA3
fmManY4wTL7yHiTK1ydAlo6UiLg+gXsgGFm4c7nTSvTTBQetn0WNzLWg8cY0S1Lk
3/niWlBCunrG7WOjbztIzukYUsFulzElDkF9gwCAYM1CoYZJWj2Lzfdmk8mzcPg0
Mz1pQIMVv+DE+g4r3XlzxubsnP6/ljtcnmaPdMjGVxaT3skUWFxQs6c20LsM7Spa
5t3MzXECgYEAw7dYn51im+AvWbPawWaKOgkxQJPgGXjdkZjx85GuqnloWAvBWt3p
qOQB7Kr4Azxq9cwX78hLN/qXyNSDfLItTdtIZNMoWDOs4JBaBUh5AX9X7itySu9S
d5nT3onmvurUrACQeEitAyeLcLyFF6qmf++hZnDJySn4m4L/0+rQH0kCgYEA8QVn
5B9naKgKjSNUn/6zQK29EeX+S3h0Gwu0YEV2cQmP7abEVZFBuB74lgjlDN5qBxmD
rf9PAwnOp/9LphV44SEbZejK3lhAhmCH1+lHDKDYZqLIR3rrmHydPZxcyw8oJMcB
Fl3f8UE8yyp5cqYg2obXPdTq3b48rYDwfssHn5MCgYEAkcHyVq03yy7jFMNFn9Nm
DmLaM2Xt+ApzuQNW7jcJBhz1AN2AWtP6OLXWWRPbMU3FutkM2p8opcATWpYqdqub
4ef1umEoIsgZcAURhe27cMoOCmqA7B3gJQKDL7E0D+uEB7VD4tD9SOQijQtZc468
AXvNkCVfolmHtQmSzZiK90ECgYEAnnzWhyybXDd70LlV0Wuzxak5dcaORGRtvMci
kle6/bOzACw0WKwO0hsTjd1FeQPcJtUBQO5sr2vIh7IZtZnTBf82O/orRLA1pede
DH1qagRuqHcMSeyrdXckErp6TlCmLiDqNyH9u3ARoOtKNzjEy831RcR3uN56mgD6
o/WwCp8CgYAWQ1fVqCv5HWMukLhjstltXwQb9Nnf9gMx5nkS80yNz1cl51Yll6LQ
jHheKOrtOP+qO+PjhsKwNQ4BQ2mjuQAFkukZzuzLSkglCDEMyoipzIUJZh4cWsAD
KIhEEshFI5jhJgRXYFoSDql3AFtTZ8UdhVyYetonz5U7UuM+Bew8GA==
-----END RSA PRIVATE KEY-----`