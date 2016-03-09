package rollauthz
import (
	"strings"
	log "github.com/Sirupsen/logrus"
	"errors"
)


//ValidAccessToken takes an authorization header value, and, if the authorization header has
//a JWT bearer token, returns the claims in the token is it is valid. A token is valid
//if it was signed with the key associated with the aud claim, and passes other tests
//of well-formed-ness.
func ValidAccessToken(authzHeader string) (map[string]interface{},error) {

	//Header format should be Bearer token
	parts := strings.SplitAfter(authzHeader, "Bearer")
	if len(parts) != 2 {
		log.Info("Unexpected authorization header format - expecting bearer token")
		return nil,errors.New("Unexpected authorization header format - expecting bearer token")
	}

	//Parse the token

	//Make sure the token is valid

	//Make sure it's no an authcode token

	//Make sure it includes a sub claim

	return nil,nil
}
