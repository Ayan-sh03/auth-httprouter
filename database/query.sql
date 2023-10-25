-- name: CreateUser :one
INSERT INTO users(
    name,email,password,otp
)VALUES(
    $1,$2,$3,$4
)
RETURNING *;


-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 LIMIT 1;

-- name: UpdateUserByEmail :exec
UPDATE users SET is_verified = TRUE WHERE email = $1;