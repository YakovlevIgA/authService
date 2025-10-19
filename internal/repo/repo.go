package repo

import (
	"context"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"seventhOne-auth/internal/config"

	"net/url"
	"time"
)

const (
	insertUserQuery = `INSERT INTO users (name, password, email, role) VALUES ($1, $2, $3, $4);`
	getUserQuery    = `SELECT id, name, password, email, role FROM users WHERE name = $1;`
	updatePassQuery = `
		UPDATE users 
		SET password = COALESCE($1, password)
		WHERE name = $2
	`
	checkQuery = `SELECT EXISTS(SELECT 1 FROM users WHERE name = $1 OR email = $2)`

	getRefreshTokenQuery = `
		SELECT refresh_token
		FROM auth_tokens
		WHERE user_id = $1;
	`

	insertRefreshTokenQuery = `
		INSERT INTO auth_tokens (user_id, refresh_token, refresh_expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`

	deleteRefreshTokenQuery = `
		DELETE FROM auth_tokens
		WHERE user_id = $1;
	`

	updateRefreshTokenQuery = `
		UPDATE auth_tokens
		SET refresh_token = $1, refresh_expires_at = $2, updated_at = NOW(), created_at = $3
		WHERE user_id = $4;
	`
)

type repository struct {
	pool   *pgxpool.Pool
	logger *zap.SugaredLogger // Добавляем логгер
}

type Repository interface {
	AddNewUser(ctx context.Context, user *User) error
	CheckUser(ctx context.Context, name string) (User, error)
	ChangePass(ctx context.Context, name, password string) error

	NewRefreshToken(ctx context.Context, params NewRefreshTokenParams) error
	DeleteRefreshToken(ctx context.Context, params DeleteRefreshTokenParams) error
	GetRefreshToken(ctx context.Context, params GetRefreshTokenParams) ([]string, error)
	UpdateRefreshToken(ctx context.Context, params UpdateRefreshTokenParams) error
}

func NewRepository(ctx context.Context, cfg config.PostgreSQL, logger *zap.SugaredLogger) (Repository, error) {
	connString := fmt.Sprintf(
		`user=%s password=%s host=%s port=%d dbname=%s sslmode=%s 
        pool_max_conns=%d pool_max_conn_lifetime=%s pool_max_conn_idle_time=%s`,
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Name,
		cfg.SSLMode,
		cfg.PoolMaxConns,
		cfg.PoolMaxConnLifetime.String(),
		cfg.PoolMaxConnIdleTime.String(),
	)
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse PostgreSQL config")
	}
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create PostgreSQL connection pool")
	}

	connCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(connCtx); err != nil {
		return nil, errors.Wrap(err, "failed to ping database")
	}

	if err := runMigrations(pool, logger); err != nil {
		return nil, errors.Wrap(err, "failed to apply migrations")
	}

	logger.Infof("Successfully connected to PostgreSQL at %s:%d", cfg.Host, cfg.Port)

	return &repository{
		pool:   pool,
		logger: logger,
	}, nil
}

func runMigrations(pool *pgxpool.Pool, logger *zap.SugaredLogger) error {
	config := pool.Config().ConnConfig

	migrateConnURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		url.PathEscape(config.User),
		url.PathEscape(config.Password),
		config.Host,
		config.Port,
		config.Database,
	)

	m, err := migrate.New("file://migrations/postgres", migrateConnURL)
	if err != nil {
		return fmt.Errorf("failed to initialize migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get migration version: %w", err)
	}

	logger.Infof("Database migrations applied. Current version: %d (dirty: %v)", version, dirty)
	return nil
}

func (r *repository) AddNewUser(ctx context.Context, user *User) error {
	var exists bool
	err := r.pool.QueryRow(ctx, checkQuery, user.Name, user.Email).Scan(&exists)
	if err != nil {
		return errors.Wrap(err, "failed to check existing user")
	}

	if exists {
		return errors.New("user with this name or email already exists")
	}

	_, err = r.pool.Exec(ctx, insertUserQuery, user.Name, user.Password, user.Email, user.Role)
	if err != nil {
		return errors.Wrap(err, "failed to create new user")
	}

	return nil
}

func (r *repository) CheckUser(ctx context.Context, name string) (User, error) {
	var user User
	err := r.pool.QueryRow(ctx, getUserQuery, name).Scan(
		&user.ID,
		&user.Name,
		&user.Password,
		&user.Email,
		&user.Role,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, fmt.Errorf("user with name %v not found", name)
		}
		return User{}, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

func (r *repository) ChangePass(ctx context.Context, name, password string) error {
	commandTag, err := r.pool.Exec(ctx, updatePassQuery, password, name)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

func (r *repository) GetRefreshToken(ctx context.Context, params GetRefreshTokenParams) ([]string, error) {
	rows, err := r.pool.Query(ctx, getRefreshTokenQuery, params.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get refresh token")
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, errors.Wrap(err, "failed to scan refresh token")
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (r *repository) NewRefreshToken(ctx context.Context, params NewRefreshTokenParams) error {
	_, err := r.pool.Exec(ctx, insertRefreshTokenQuery, params.UserID, params.Token, params.Expires)
	if err != nil {
		return errors.Wrap(err, "failed to insert refresh token")
	}
	return nil
}

func (r *repository) DeleteRefreshToken(ctx context.Context, params DeleteRefreshTokenParams) error {
	_, err := r.pool.Exec(ctx, deleteRefreshTokenQuery, params.UserID)
	if err != nil {
		return errors.Wrap(err, "failed to delete refresh token")
	}
	return nil
}

func (r *repository) UpdateRefreshToken(ctx context.Context, params UpdateRefreshTokenParams) error {
	_, err := r.pool.Exec(ctx, updateRefreshTokenQuery, params.Token, params.Expires, params.CreatedDate, params.UserID)
	if err != nil {
		return errors.Wrap(err, "failed to update refresh token")
	}
	return nil
}
func RollbackMigrations(repo Repository, logger *zap.SugaredLogger) error {

	r, ok := repo.(*repository)
	if !ok {
		return fmt.Errorf("repository is not of expected type *repository")
	}

	pool := r.pool

	config := pool.Config().ConnConfig

	migrateConnURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		url.PathEscape(config.User),
		url.PathEscape(config.Password),
		config.Host,
		config.Port,
		config.Database)

	m, err := migrate.New(
		"file://migrations/postgres",
		migrateConnURL)
	if err != nil {
		return fmt.Errorf("failed to initialize migrator: %w", err)
	}
	defer m.Close()

	if err := m.Down(); err != nil {
		if err == migrate.ErrNoChange {
			logger.Info("No migrations to rollback")
			return nil
		}
		return fmt.Errorf("failed to rollback migrations: %w", err)
	}

	logger.Info("Migrations rolled back successfully")
	return nil
}
