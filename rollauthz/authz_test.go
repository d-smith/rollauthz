package rollauthz
import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestNonBearerTokenHeaderValusRejected(t *testing.T) {
	claims, err := ValidAccessToken("not a bearer token beader")
	assert.Nil(t,claims)
	assert.NotNil(t, err)
}
