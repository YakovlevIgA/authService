package service

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	fromproto "seventhOne-auth/protos/gen/proto"
	"time"
)

type AddUserRequest struct {
	Name     string `json:"name" validate:"required"`
	Password string `json:"password" validate:"required"`
	Email    string `json:"email" validate:"required"`
	Role     string `json:"role" validate:"required,oneof=user admin manager"`
}

type ChangePassRequest struct {
	Name     string `json:"name" validate:"required"`
	Password string `json:"password" validate:"required"`
}

const (
	ErrUnknown                  = "try it a little later or check the data you entered"
	ErrUserAuthAlreadyExist     = "user auth already exist"
	ErrUserNotFound             = "User not found"
	ErrValidatePassword         = "Incorrect email or password. Number of attempts:"
	ErrValidateJwt              = "not authorized"
	ErrTokenNotFound            = "refresh token not found"
	ErrLockForCheckPassword     = "Exceeded the maximum number of attempts.\nTry again at"
	ErrPasswordMatchOldPassword = "Please enter new password"
)

func lockForActionErr(time time.Time) error {

	err := status.New(codes.Unavailable, ErrLockForCheckPassword)
	err, _ = err.WithDetails(&fromproto.Err{
		ExpirationTime: timestamppb.New(time),
	})
	return err.Err()
}
