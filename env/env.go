package env

import (
	"log"
	"os"
)

func GetValue(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Println("Missing .env field:", key)
		os.Exit(1)
	}
	return value
}
