// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.22.0
// source: query.sql

package db

import (
	"context"
	"database/sql"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users(
    name,email,password,otp
)VALUES(
    $1,$2,$3,$4
)
RETURNING id, name, email, password, otp, is_verified
`

type CreateUserParams struct {
	Name     string
	Email    string
	Password string
	Otp      sql.NullString
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser,
		arg.Name,
		arg.Email,
		arg.Password,
		arg.Otp,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Email,
		&i.Password,
		&i.Otp,
		&i.IsVerified,
	)
	return i, err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT id, name, email, password, otp, is_verified FROM users WHERE email = $1 LIMIT 1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Email,
		&i.Password,
		&i.Otp,
		&i.IsVerified,
	)
	return i, err
}

const updateUserByEmail = `-- name: UpdateUserByEmail :exec
UPDATE users SET is_verified = TRUE WHERE email = $1
`

func (q *Queries) UpdateUserByEmail(ctx context.Context, email string) error {
	_, err := q.db.ExecContext(ctx, updateUserByEmail, email)
	return err
}
