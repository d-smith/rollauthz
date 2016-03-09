package rollauthz
import (
	"strings"
	log "github.com/Sirupsen/logrus"
	"os"
)

var vaultEndpoint string
var vaultToken string

func init() {
	initFromEnv()
}

//We provide a function to call from init so we can manipulate the config settings in unit tests
func initFromEnv() {
	vaultEndpoint = os.Getenv("VAULT_ADDR")
	if vaultEndpoint == "" {
		log.Warn("Missing Configuration: VAULT_ADDR env variable not specified")
	}

	vaultToken = os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		log.Warn("Missing configuration: VAULT_TOKEN env variable not specified")
	}
}

type ErrConfig struct {}

func (ec ErrConfig) Error() string {
	return "rollauthz msiconfigured: VAULT_ADDR and VAULT_TOKEN environment variables must be specified"
}

type ErrNonBearerHeader struct {}

func (e ErrNonBearerHeader) Error() string {
	return "unexpected authorization header format - expecting bearer token"
}

func checkConfig() error {
	if vaultEndpoint == "" || vaultToken == "" {
		return ErrConfig{}
	}

	return nil
}




//ValidAccessToken takes an authorization header value, and, if the authorization header has
//a JWT bearer token, returns the claims in the token is it is valid. A token is valid
//if it was signed with the key associated with the aud claim, and passes other tests
//of well-formed-ness.
func ValidAccessToken(authzHeader string) (map[string]interface{},error) {
	if err := checkConfig(); err != nil {
		return nil,err
	}

	//Header format should be Bearer token
	parts := strings.SplitAfter(authzHeader, "Bearer")
	if len(parts) != 2 {
		log.Info("Unexpected authorization header format - expecting bearer token")
		return nil,ErrNonBearerHeader{}
	}

	//Parse the token

	//Make sure the token is valid

	//Make sure it's no an authcode token

	//Make sure it includes a sub claim

	return nil,nil
}
