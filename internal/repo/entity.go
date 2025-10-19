package repo

import (
	"database/sql"
	"time"
)

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

type NewRefreshTokenParams struct {
	UserID  int
	Token   string
	Expires time.Time
}

type DeleteRefreshTokenParams struct {
	UserID int
}

type GetRefreshTokenParams struct {
	UserID int
}

type UpdateRefreshTokenParams struct {
	UserID      int
	Token       string
	Expires     time.Time
	CreatedDate sql.NullTime
}

type UpdatePasswordParams struct {
	UserID   int
	Password string
}

type AddUserParams struct {
	Name     string
	Password string
	Email    string
	Role     string
}
