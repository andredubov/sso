package main

import (
	"fmt"
	"log"

	"github.com/andredubov/sso/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(cfg)
}
