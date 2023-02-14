package utils

import (
	"bufio"
	"os"
)

func GetFileScanner(filePath string) *bufio.Scanner {
	f, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(f)
	return scanner
}
