package rollauthz

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/xtraclabs/rollsecrets/secrets"
	rolltoken "github.com/xtraclabs/rollsecrets/token"
	"strings"
)

type RollAuthZ struct {
	SecretsRepo secrets.SecretsRepo
}

type ErrNonBearerHeader struct{}

func (e ErrNonBearerHeader) Error() string {
	return "unexpected authorization header format - expecting bearer token"
}

type ErrNoVaultClient struct{}

func (e ErrNoVaultClient) Error() string {
	return "no vault client configured for RollAuthZ"
}

type ErrParse struct {
	source error
}

func (e ErrParse) Error() string {
	return fmt.Sprintf("error parsing token: %s", e.source)
}

//ValidateAccessToken takes an authorization header value, and, if the authorization header has
//a JWT bearer token, returns the claims in the token is it is valid. A token is valid
//if it was signed with the key associated with the aud claim, and passes other tests
//of well-formed-ness.
func (raz RollAuthZ) ValidateAccessToken(authzHeader string) (map[string]interface{}, error) {

	//Header format should be Bearer token
	parts := strings.SplitAfter(authzHeader, "Bearer")
	if len(parts) != 2 {
		log.Info("Unexpected authorization header format - expecting bearer token")
		return nil, ErrNonBearerHeader{}
	}

	//Parse the token
	bearerToken := strings.TrimSpace(parts[1])
	token, err := jwt.Parse(bearerToken, rolltoken.GenerateKeyExtractionFunction(raz.SecretsRepo))
	if err != nil {
		return nil, ErrParse{err}
	}
	println(token)

	//Make sure the token is valid

	//Make sure it's no an authcode token

	//Make sure it includes a sub claim

	return nil, nil
}
