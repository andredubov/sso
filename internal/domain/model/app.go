package model

type App struct {
	ID     string `db:"id"`
	Name   string `db:"name"`
	Secret string `db:"secret"`
}
