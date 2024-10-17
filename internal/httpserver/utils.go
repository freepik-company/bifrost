package httpserver

import (
	"crypto/rand"
	"fmt"
)

func generateRandToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
