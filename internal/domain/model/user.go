package model

type User struct {
	ID       string `db:"id"`
	Email    string `db:"email"`
	Password string `db:"password_hash"`
	IsAdmin  bool   `db:"is_admin"`
}
