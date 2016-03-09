package rollauthz

import (
	"github.com/stretchr/testify/assert"
	"github.com/xtraclabs/rollsecrets/secrets"
	"github.com/xtraclabs/rollsecrets/secrets/mocks"
	rolltoken "github.com/xtraclabs/rollsecrets/token"
	"testing"
)

const (
	aToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBsaWNhdGlvbiI6ImRldiBwb3J0YWwiLCJhdWQiOiIzNGU0M2YwYS04N2RlLTQ3OTMtNTJjOS1iZGQ1MTgyNGYwNWMiLCJleHAiOjE0NTY5MjQ3OTEsImlhdCI6MTQ1NjgzODM5MSwianRpIjoiNDJjYmNiZDItZGQ5OS00NWVlLTcwMzYtNTM5ZjU5YjM1Y2FmIiwic2NvcGUiOiIiLCJzdWIiOiJ1c2VyIn0.no-7QKPf0XrrJiq44dWDHoirpxOR2N0mzvyrihxllv8TUix-vQdjao0fvHjzUA2X9rZWOcXmZC6zzJDlaF0kVO-mwSAa74btZI4oxsp4zRX_mtwwo5THsktAKcedzWezB-SrQqV-8NrNEjLbdl27rAydvAfc14bp9EV67fzyQws"
)

func TestNonBearerTokenHeaderValuesRejected(t *testing.T) {
	raz := RollAuthZ{}
	claims, err := raz.ValidateAccessToken("not a bearer token beader")
	assert.Nil(t, claims)
	if assert.NotNil(t, err) {
		_, ok := err.(ErrNonBearerHeader)
		assert.True(t, ok, "expected a ErrNonBearerHeader error")
	}
}

func TestUnparsableToken(t *testing.T) {
	raz := RollAuthZ{}
	claims, err := raz.ValidateAccessToken("Bearer whoops")
	assert.Nil(t, claims)
	if assert.NotNil(t, err) {
		_, ok := err.(ErrParse)
		assert.True(t, ok, "expected a ErrParse error")
	}
}

func TestParseGoodToken(t *testing.T) {
	privateKey, publicKey, err := secrets.GenerateKeyPair()
	assert.Nil(t, err)

	secretsMock := new(mocks.SecretsRepo)
	secretsMock.On("RetrievePrivateKeyForApp", "1111-2222-3333333-4444444").Return(privateKey, nil)
	secretsMock.On("RetrievePublicKeyForApp", "1111-2222-3333333-4444444").Return(publicKey, nil)

	token, err := rolltoken.GenerateToken("a-subject", "", "1111-2222-3333333-4444444", "app name", privateKey)
	assert.Nil(t, err)

	raz := RollAuthZ{
		secretsMock,
	}
	_, err = raz.ValidateAccessToken("Bearer " + token)
	assert.Nil(t, err)
}
