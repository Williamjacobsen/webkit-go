package store

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	Path string
	DB   *sql.DB
}

func (s *Store) Init_db() {
	var err error
	s.DB, err = sql.Open("sqlite3", s.Path)
	if err != nil {
		log.Fatal(err)
	}

	if err := s.DB.Ping(); err != nil {
		log.Fatal(err)
	}
}

func (s *Store) Close() {
	s.DB.Close()
}
