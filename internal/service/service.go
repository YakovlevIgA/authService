package service

import (
	"context"
	"database/sql"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"time"

	//"database/sql"
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"seventhOne-auth/internal/config"
	"seventhOne-auth/internal/repo"
	"seventhOne-auth/pkg/jwt"
	"seventhOne-auth/pkg/secure"
	"seventhOne-auth/pkg/validator"
	fromproto "seventhOne-auth/protos/gen/proto"
	//"github.com/pkg/errors"
	//"github.com/rogpeppe/go-internal/cache"
	"go.uber.org/zap"
	//"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	//"os"
	//"strconv"
	//"strings"
	//"time"
)

type authServer struct {
	repo                  repo.Repository
	cfg                   config.AppConfig
	jwt                   jwt.JWTClient
	log                   *zap.SugaredLogger
	numberPasswordEntries *cache.Cache
	fromproto.UnimplementedAuthServiceServer
}

// NewService - конструктор сервиса
func NewService(cfg config.AppConfig, repo repo.Repository, log *zap.SugaredLogger, jwt jwt.JWTClient) fromproto.AuthServiceServer {
	return &authServer{
		cfg:  cfg,
		repo: repo,
		log:  log,
		jwt:  jwt,
		numberPasswordEntries: cache.New(
			cfg.System.LockPasswordEntry,
			cfg.System.LockPasswordEntry,
		)}
}

func (a *authServer) Register(ctx context.Context, request *fromproto.RegisterRequest) (*fromproto.RegisterResponse, error) {

	if err := validator.Validate(ctx, request); err != nil {
		a.log.Error("Invalid registration request",
			zap.String("username", request.Username),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	if valid, err := secure.IsValidPassword(request.Password); !valid {
		a.log.Warn("Weak password provided",
			zap.String("username", request.Username),
			zap.Error(err),
		)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Хэширование пароля
	hashedPassword, err := secure.HashPassword(request.Password)
	if err != nil {
		a.log.Error("Failed to hash password",
			zap.String("username", request.Username),
			zap.Error(err),
		)
		return nil, status.Error(codes.Internal, "failed to process password")
	}

	role := strings.TrimSpace(request.GetRole())
	if role != "user" && role != "admin" && role != "manager" {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role")
	}

	// Сохранение пользователя в базу
	err = a.repo.AddNewUser(ctx, &repo.User{
		Name:     request.GetUsername(),
		Password: hashedPassword,
		Email:    request.GetEmail(),
		Role:     request.GetRole(),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			a.log.Info("User already exists",
				zap.String("username", request.Username),
				zap.String("email", request.Email),
			)
			return nil, status.Error(codes.AlreadyExists, ErrUserAuthAlreadyExist)
		}

		a.log.Error("Failed to create user",
			zap.String("username", request.Username),
			zap.String("email", request.Email),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	a.log.Info("User successfully registered",
		zap.String("username", request.Username),
		zap.String("email", request.Email),
	)

	return &fromproto.RegisterResponse{
		Message: fmt.Sprintf("User %s created successfully", request.Username),
	}, nil
}

func (a *authServer) Login(ctx context.Context, request *fromproto.LoginRequest) (*fromproto.LoginResponse, error) {
	if err := validator.Validate(ctx, request); err != nil {
		a.log.Error("Invalid login request",
			zap.String("name", request.Username),
			zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	userFromDB, err := a.repo.CheckUser(ctx, request.Username)
	if err != nil {
		a.log.Error("Failed to find user", zap.String("name", request.Username), zap.Error(err))
		return nil, status.Error(codes.NotFound, "failed to find user")
	}

	// Проверка пароля
	if err := bcrypt.CompareHashAndPassword([]byte(userFromDB.Password), []byte(request.Password)); err != nil {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}

	// Создание токенов с ролью
	tokens, err := a.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: int64(userFromDB.ID),
		Name:   request.Username,
		Role:   userFromDB.Role, // <- роль добавлена
	})
	if err != nil {
		a.log.Errorf("failed to create access token: %s", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Парсинг refresh token для получения времени истечения
	data, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: tokens.RefreshToken,
	})
	if err != nil {
		a.log.Error("Failed to parse token to get expires in login token creating process", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	// Сохранение refresh token
	err = a.repo.NewRefreshToken(ctx, repo.NewRefreshTokenParams{
		UserID:  userFromDB.ID,
		Token:   tokens.RefreshToken,
		Expires: data.Expires,
	})
	if err != nil {
		a.log.Error("failed to save refresh token", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to save refresh token")
	}

	return &fromproto.LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Role:         userFromDB.Role,
	}, nil
}

func (a *authServer) DropPass(ctx context.Context, request *fromproto.DropPassRequest) (*fromproto.DropPassResponse, error) {
	if err := validator.Validate(ctx, request); err != nil {
		a.log.Error("Invalid login request",
			zap.String("name", request.Username),
			zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	token, err := auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "missing auth token")
	}

	data, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: token,
	})
	if err != nil {
		a.log.Error("Failed to parse token in DropPass", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	if data.Name != request.Username {
		a.log.Warn("Username mismatch in token and request",
			zap.String("from_token", data.Name),
			zap.String("from_request", request.Username))
		return nil, status.Error(codes.PermissionDenied, "username in token does not match request")
	}

	hashedPassword, err := secure.HashPassword(request.Newpassword)
	if err != nil {
		a.log.Error("Failed to hash password", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to process password")
	}

	err = a.repo.ChangePass(ctx, request.Username, hashedPassword)
	if err != nil {
		a.log.Errorf("failed to change password: %s", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	err = a.repo.DeleteRefreshToken(ctx, repo.DeleteRefreshTokenParams{
		UserID: int(data.UserId),
	})
	if err != nil {
		a.log.Error("failed to delete refresh token",
			zap.Int64("userID", data.UserId),
			zap.Error(err),
		)
		return nil, status.Error(codes.Internal, "could not delete refresh token")
	}

	return &fromproto.DropPassResponse{
		Success: true}, nil
}

func (a *authServer) Validate(
	ctx context.Context,
	req *fromproto.ValidateRequest,
) (
	*fromproto.ValidateResponse, error,
) {

	check, err := a.jwt.ValidateToken(&jwt.ValidateTokenParams{
		Token: req.AccessToken,
	})

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	if !check {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	accessData, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.AccessToken,
	})

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	_, err = a.repo.GetRefreshToken(ctx, repo.GetRefreshTokenParams{
		UserID: int(accessData.UserId),
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
		}

		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &fromproto.ValidateResponse{
		UserId: accessData.UserId,
		Role:   accessData.Role,
	}, nil
}

func (a *authServer) Refresh(
	ctx context.Context,
	req *fromproto.RefreshRequest,
) (
	*fromproto.RefreshResponse, error,
) {

	check, err := a.jwt.ValidateToken(&jwt.ValidateTokenParams{
		Token: req.RefreshToken,
	})
	if err != nil {
		a.log.Errorf("validate refresh token err")
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}
	if !check {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}
	accessData, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.AccessToken,
	})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	refreshData, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.RefreshToken,
	})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}
	if accessData.UserId != refreshData.UserId {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	rtToken, err := a.repo.GetRefreshToken(ctx, repo.GetRefreshTokenParams{
		UserID: int(refreshData.UserId),
	})
	if err != nil {
		a.log.Errorf("get refresh token err")
		if err == sql.ErrNoRows {
			return nil, status.Error(codes.NotFound, ErrTokenNotFound)
		}
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	if len(rtToken) == 0 {
		a.log.Errorf("len(rtToken) == 0")
		return nil, status.Error(codes.NotFound, ErrTokenNotFound)
	}

	if rtToken[0] != req.RefreshToken {
		a.log.Errorf("rtToken[0] != req.RefreshToken")
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	tokens, err := a.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: refreshData.UserId,
		Name:   refreshData.Name,
	})

	if err != nil {
		a.log.Errorf("create tokens error")
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	data, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: tokens.RefreshToken,
	})
	if err != nil {
		a.log.Error("Failed to parse token while taking data.Expires while Refreshing", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	err = a.repo.UpdateRefreshToken(ctx, repo.UpdateRefreshTokenParams{
		Token:       tokens.RefreshToken,
		Expires:     data.Expires,
		CreatedDate: sql.NullTime{Time: time.Now(), Valid: true},
		UserID:      int(refreshData.UserId),
	})

	if err != nil {
		a.log.Errorf("update refresh token err")
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &fromproto.RefreshResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Role:         accessData.Role,
	}, nil
}
