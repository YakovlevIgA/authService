package jwt

import "time"

type GetDataFromTokenParams struct {
	Token string
}

type GetDataFromTokenResponse struct {
	UserId  int64
	Name    string
	Role    string
	Expires time.Time
}
type CreateTokenParams struct {
	UserId int64
	Name   string
	Role   string
}

type CreateTokenResponse struct {
	AccessToken  string
	RefreshToken string
}

type ValidateTokenParams struct {
	Token string
}
