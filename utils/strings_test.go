package utils

import (
	"fmt"
	"testing"
)

func TestEscapeString(t *testing.T) {
	inputs := []string{"abc", "ab\\c", "ab=c", "ab&c"}
	want := []string{"abc", "ab\\\\c", "ab\\=c", "ab\\&c"}
	for i := 0; i < len(inputs); i++ {
		if EscapeString(inputs[i]) != want[i] {
			t.Fatalf("Escape Strings failed")
		}
	}
}

func TestParseURLEncoding(t *testing.T) {
	profile := map[string]string{"email": "a&b.com&k=v", "uid": "10", "role": "user"}
	url := URLEncodeProfile(profile)
	parsedProfile := ParseURLEncoding(url)
	for k, v := range profile {
		if parsedProfile[k] != v {
			t.Fatalf("Failed to parse url encoding")
		}
	}
	if len(profile) != len(parsedProfile) {
		t.Fatalf("Failed url encoding")
	}
}

func TestUserCookie(t *testing.T) {
	userData := "helloworld;admin=true;"
	cookie := GenerateUserCookie(userData)
	role := FindKeyInCookie(cookie, "admin")
	if role != "" {
		t.Fatalf("Invalid Key found in Cookie")
	}
	data := FindKeyInCookie(cookie, "userdata")
	if data != userData {
		fmt.Println(data, userData)
		t.Fatalf("Invalid userData found in Cookie")
	}
}
