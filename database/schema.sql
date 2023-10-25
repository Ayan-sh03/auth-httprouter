CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    otp TEXT,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX email_index ON users (email);
