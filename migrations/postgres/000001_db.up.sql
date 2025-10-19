CREATE TABLE users (
                       id SERIAL PRIMARY KEY,
                       name TEXT NOT NULL,
                       password TEXT NOT NULL,
                       email TEXT NOT NULL,
                       role TEXT NOT NULL DEFAULT 'user',
                       CONSTRAINT role_check CHECK (role IN ('user', 'admin', 'manager'))
);

CREATE TABLE auth_tokens (
                             user_id INTEGER NOT NULL PRIMARY KEY,
                             refresh_token TEXT NOT NULL UNIQUE,
                             refresh_expires_at TIMESTAMPTZ NOT NULL,
                             created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                             updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                             CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);


CREATE INDEX idx_auth_tokens_user_id ON auth_tokens(user_id);
