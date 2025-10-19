package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"

	"github.com/rs/zerolog/log"
)

type JWTClient interface {
	CreateToken(params *CreateTokenParams) (*CreateTokenResponse, error)
	ValidateToken(params *ValidateTokenParams) (bool, error)
	GetDataFromToken(params *GetDataFromTokenParams) (*GetDataFromTokenResponse, error)
}

type jwtClient struct {
	privateKey       *rsa.PrivateKey
	publicKey        *rsa.PublicKey
	accessTokenTime  time.Duration
	refreshTokenTime time.Duration
}

func NewJWTClient(
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
	accessTokenTime time.Duration,
	refreshTokenTime time.Duration,
) *jwtClient {
	return &jwtClient{
		privateKey:       privateKey,
		publicKey:        publicKey,
		accessTokenTime:  accessTokenTime,
		refreshTokenTime: refreshTokenTime,
	}
}

func (a *jwtClient) CreateToken(params *CreateTokenParams) (*CreateTokenResponse, error) {
	accessToken, err := a.newToken(params, a.accessTokenTime)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	refreshToken, err := a.newToken(params, a.refreshTokenTime)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	return &CreateTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a *jwtClient) ValidateToken(params *ValidateTokenParams) (bool, error) {
	token, err := jwt.Parse(params.Token, func(token *jwt.Token) (interface{}, error) {
		return a.publicKey, nil
	})

	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		expirationTime := int64(claims["exp"].(float64))
		if expirationTime > time.Now().Unix() {
			return true, nil
		}
	}
	return false, nil
}

func (a *jwtClient) GetDataFromToken(params *GetDataFromTokenParams) (*GetDataFromTokenResponse, error) {
	token, err := jwt.Parse(params.Token, func(token *jwt.Token) (interface{}, error) {
		return a.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims structure")
	}

	userId, ok1 := claims["userId"].(float64)
	name, ok2 := claims["name"].(string)
	role, ok3 := claims["role"].(string)
	exp, ok4 := claims["exp"].(float64)

	if !ok1 || !ok2 || !ok3 || !ok4 {
		log.Error().Fields(map[string]interface{}{
			"userIdOk": ok1, "nameOk": ok2, "roleOk": ok3, "expOk": ok4,
		}).Msg("Failed to parse token claims")
		return nil, errors.New("invalid token claims")
	}

	expires := time.Unix(int64(exp), 0)

	return &GetDataFromTokenResponse{
		UserId:  int64(userId),
		Name:    name,
		Role:    role,
		Expires: expires,
	}, nil
}

func (a *jwtClient) newToken(params *CreateTokenParams, ttl time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = jwt.MapClaims{
		"userId": params.UserId,
		"name":   params.Name,
		"role":   params.Role,
		"exp":    time.Now().Add(ttl).Unix(),
	}

	tokenString, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
}
