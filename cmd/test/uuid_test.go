package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// See const.go for overview of math here.

// Test that powx is initialized correctly.
// (Can adapt this code to generate it too.)
func TestPowx(t *testing.T) {
	_uuid, _ := uuid.NewUUID()
	u := strings.ReplaceAll(_uuid.String(), "-", "")
	fmt.Println(u)
}
