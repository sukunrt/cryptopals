package main

import (
	"errors"
	"fmt"
	"math/rand"
)

func init() {
	// b := make([]byte, 8)
	// crand.Read(b)
	// rand.Seed(int64(binary.BigEndian.Uint64(b)))
	rand.Seed(35)
}

type expr struct {
	x     string
	v, vv int
}

func (e expr) String() string {
	return fmt.Sprintf("pb(%s[%d], %d)", e.x, e.v, e.vv)
}

func parseExpr(s string, i int) (expr, int, error) {
	if s[i] != 'a' && s[i] != 'b' && s[i] != 'c' && s[i] != 'd' {
		return expr{}, 0, errors.New("failed")
	}
	c := s[i]
	var v int
	j := i + 1
	for ; j < len(s); j++ {
		if s[j] == ',' {
			break
		}
		v = v*10 + (int(s[j]) - '0')
	}
	var vv int
	for j = j + 1; j < len(s); j++ {
		if s[j] == ',' || s[j] == ' ' {
			break
		}
		vv = vv*10 + (int(s[j]) - '0')
	}
	return expr{string(c), v, vv}, j, nil
}

func transformS(s string) string {
	items := []string{}
	state := "st"
	var lexpr expr
	var rexpr expr
	var err error
	var c = s[0]
	var n = s[1] - '0'
	for i := 2; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '=' || s[i] == ',' {
			continue
		}
		switch state {
		case "st":
			lexpr, i, err = parseExpr(s, i)
			if err != nil {
				panic(err)
			}
			state = "ed"
			i--
		case "ed":
			if s[i] == '1' {
				items = append(items, fmt.Sprintf(" ^ %s ^ ob(%d)", lexpr.String(), lexpr.vv))
			} else if s[i] == '0' {
				items = append(items, fmt.Sprintf(" ^ %s ", lexpr.String()))
			} else {
				rexpr, i, err = parseExpr(s, i)
				if err != nil {
					panic(err)
				}
				i--
				items = append(items, fmt.Sprintf("^ %s ^ %s", lexpr.String(), rexpr.String()))
				lexpr = expr{}
				rexpr = expr{}
			}
			state = "st"
		}
	}
	ss := ""
	for _, item := range items {
		ss += item
	}
	return fmt.Sprintf("%sn := %s[%d] %s", string(c), string(c), n, ss)
}

func main() {
	fmt.Println(transformS("d3 d3,13 = 1, d3,14 = 1, d3,15 = 1, d3,17 = 0, d3,20 = 0, d3,21 = 1, d3,22 = 1, d3,23 = 0, d3,26 = 1, d3,30 = a3,30"))
}
