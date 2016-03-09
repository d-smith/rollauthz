package rollauthz
import (
	"testing"
	"github.com/stretchr/testify/assert"
	"os"
)

func TestMisconfiguration(t *testing.T) {
	os.Unsetenv("VAULT_ADDR")
	os.Unsetenv("VAULT_TOKEN")

	_, err := ValidAccessToken("sure")
	if assert.NotNil(t, err) {
		_, ok := err.(ErrConfig)
		assert.True(t, ok)
	}
}

func TestNonBearerTokenHeaderValuesRejected(t *testing.T) {
	os.Setenv("VAULT_ADDR", "config")
	os.Setenv("VAULT_TOKEN", "config")
	initFromEnv()


	claims, err := ValidAccessToken("not a bearer token beader")
	assert.Nil(t,claims)
	if assert.NotNil(t, err) {
		_,ok := err.(ErrNonBearerHeader)
		assert.True(t, ok, "expected a ErrNonBearerHeader error")
	}
}
