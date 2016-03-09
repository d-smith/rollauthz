package rollauthz

import (
	"github.com/stretchr/testify/assert"
	"github.com/xtraclabs/rollsecrets/secrets"
	"github.com/xtraclabs/rollsecrets/secrets/mocks"
	rolltoken "github.com/xtraclabs/rollsecrets/token"
	"testing"
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

	token, err := rolltoken.GenerateToken("a-subject", "laser", "1111-2222-3333333-4444444", "app name", privateKey)
	assert.Nil(t, err)

	raz := RollAuthZ{
		secretsMock,
	}
	claims, err := raz.ValidateAccessToken("Bearer " + token)
	assert.Nil(t, err)
	if assert.NotNil(t, claims) {
		assert.True(t, claims["jti"] != "")
		assert.Equal(t, "a-subject", claims["sub"])
		assert.Equal(t, "app name", claims["application"])
		assert.Equal(t, "laser", claims["scope"])
		assert.Equal(t, "1111-2222-3333333-4444444", claims["aud"])
		assert.NotNil(t, claims["exp"])
		assert.NotNil(t, claims["iat"])
	}
}

func TestAuthCodeUsedForAccess(t *testing.T) {

	privateKey, publicKey, err := secrets.GenerateKeyPair()
	assert.Nil(t, err)

	secretsMock := new(mocks.SecretsRepo)
	secretsMock.On("RetrievePrivateKeyForApp", "1111-2222-3333333-4444444").Return(privateKey, nil)
	secretsMock.On("RetrievePublicKeyForApp", "1111-2222-3333333-4444444").Return(publicKey, nil)

	token, err := rolltoken.GenerateCode("a-subject", "", "1111-2222-3333333-4444444", privateKey)
	assert.Nil(t, err)

	raz := RollAuthZ{
		secretsMock,
	}
	_, err = raz.ValidateAccessToken("Bearer " + token)
	if assert.NotNil(t, err) {
		_, ok := err.(ErrAuthCodeUsedForAccess)
		assert.True(t, ok, "expected a rollauthz.ErrAuthCodeUsedForAccess error")
	}

}

func TestClaimsMissingSub(t *testing.T) {
	privateKey, publicKey, err := secrets.GenerateKeyPair()
	assert.Nil(t, err)

	secretsMock := new(mocks.SecretsRepo)
	secretsMock.On("RetrievePrivateKeyForApp", "1111-2222-3333333-4444444").Return(privateKey, nil)
	secretsMock.On("RetrievePublicKeyForApp", "1111-2222-3333333-4444444").Return(publicKey, nil)

	token, err := rolltoken.GenerateToken("", "", "1111-2222-3333333-4444444", "app name", privateKey)
	assert.Nil(t, err)

	raz := RollAuthZ{
		secretsMock,
	}
	_, err = raz.ValidateAccessToken("Bearer " + token)
	if assert.NotNil(t, err) {
		_, ok := err.(ErrClaimsMissingSub)
		assert.True(t, ok, "expected a rollauthz.ErrClaimsMissingSub error")
	}
}

func TestInvalidSignature(t *testing.T) {
	privateKey, publicKey, err := secrets.GenerateKeyPair()
	assert.Nil(t, err)

	anotherPrivateKey, _, err := secrets.GenerateKeyPair()
	assert.Nil(t, err)

	secretsMock := new(mocks.SecretsRepo)
	secretsMock.On("RetrievePrivateKeyForApp", "1111-2222-3333333-4444444").Return(privateKey, nil)
	secretsMock.On("RetrievePublicKeyForApp", "1111-2222-3333333-4444444").Return(publicKey, nil)

	token, err := rolltoken.GenerateToken("bad-guy-or-gal", "", "1111-2222-3333333-4444444", "app name", anotherPrivateKey)
	assert.Nil(t, err)

	raz := RollAuthZ{
		secretsMock,
	}
	_, err = raz.ValidateAccessToken("Bearer " + token)
	if assert.NotNil(t, err) {
		_, ok := err.(ErrParse)
		assert.True(t, ok, "expected a rollauthz.ErrParse error")
	}
}
