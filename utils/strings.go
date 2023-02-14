package utils

func ParseURLEncoding(s string) map[string]string {
	res := make(map[string]string)
	prev := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '&' {
			for j := prev; j < i; j++ {
				if s[j] == '\\' {
					j++
					continue
				}
				if s[j] == '=' {
					k, v := s[prev:j], s[j+1:i]
					res[RemoveEscapeChars(k)] = RemoveEscapeChars(v)
					break
				}
			}
			prev = i + 1
		}
	}
	for j := prev; j < len(s); j++ {
		if s[j] == '\\' {
			j++
			continue
		}
		if s[j] == '=' {
			k, v := s[prev:j], s[j+1:]
			res[RemoveEscapeChars(k)] = RemoveEscapeChars(v)
			break
		}
	}
	return res
}

func RemoveEscapeChars(s string) string {
	res := make([]byte, 0)
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
		}
		res = append(res, s[i])
	}
	return string(res)
}

func EscapeString(s string) string {
	res := make([]byte, 0)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '&', '=', ';':
			res = append(res, '\\', s[i])
		default:
			res = append(res, s[i])
		}
	}
	return string(res)
}

func URLEncodeProfile(m map[string]string) string {
	res := make([]byte, 0)
	res = append(res, []byte("email="+EscapeString(m["email"]))...)
	res = append(res, []byte("&uid="+EscapeString(m["uid"]))...)
	res = append(res, []byte("&role="+EscapeString(m["role"]))...)
	return string(res)
}

func ProfileFor(email string) map[string]string {
	return map[string]string{
		"email": email,
		"uid":   "10",
		"role":  "user",
	}
}

func GenerateUserCookie(userData string) string {
	return "comment1=cooking%20MCs;userdata=" + EscapeString(userData) + ";comment2=%20like%20a%20pound%20of%20bacon"
}

func FindKeyInCookie(cookie, k string) string {
	kvs := make(map[string]string)
	prev := 0
	for i := 0; i < len(cookie); i++ {
		if cookie[i] == '\\' {
			i++
			continue
		}
		if cookie[i] == ';' {
			for j := prev; j < i; j++ {
				if cookie[j] == '\\' {
					j++
					continue
				}
				if cookie[j] == '=' {
					k, v := RemoveEscapeChars(cookie[prev:j]), RemoveEscapeChars(cookie[j+1:i])
					kvs[k] = v
					break
				}
			}
			prev = i + 1
		}
	}
	for i := prev; i < len(cookie); i++ {
		if cookie[i] == '\\' {
			i++
			continue
		}
		if cookie[i] == '=' {
			k, v := RemoveEscapeChars(cookie[prev:i]), RemoveEscapeChars(cookie[i+1:])
			kvs[k] = v
			break
		}
	}
	v, ok := kvs[k]
	if ok {
		return v
	}
	return ""
}
