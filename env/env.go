package env

import (
	"log"
	"os"
)

func GetValue(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalln("Missing .env field:", key)
	}
	return value
}
