package main

import (
	"fmt"
	"math/rand"
	"strings"
)

type exprType int

const (
	exprTypeVariable exprType = iota
	exprTypeConstant
)

func init() {
	// b := make([]byte, 8)
	// crand.Read(b)
	// rand.Seed(int64(binary.BigEndian.Uint64(b)))
	rand.Seed(35)
}

type expr struct {
	tp    exprType
	x     string
	v, vv int
}

type cond struct {
	lexpr, rexpr expr
}

func (c cond) String() string {
	switch c.rexpr.tp {
	case exprTypeConstant:
		if c.rexpr.v == 0 {
			return fmt.Sprintf(" %s ", c.lexpr)
		} else {
			return fmt.Sprintf(" %s ^ ob(%d)", c.lexpr, c.rexpr.v)
		}
	case exprTypeVariable:
		return fmt.Sprintf(" %s ^ %s", c.lexpr, c.rexpr)
	default:
		return "unknown"
	}
}

func (e expr) String() string {
	return fmt.Sprintf("pb(wmd.%s[%d], %d)", e.x, e.v, e.vv)
}

func parseExpr(s string, i int) (expr, int, error) {
	if !strings.Contains("abcd10", string(s[i])) {
		return expr{}, 0, fmt.Errorf("invalid starting value %s", string(s[i]))
	}
	c := s[i]
	switch s[i] {
	case '0', '1':
		return expr{tp: exprTypeConstant, v: int(s[i] - '0')}, i, nil
	default:
		var v int
		j := i + 1
		for ; j < len(s); j++ {
			if s[j] == ',' {
				break
			}
			v = v*10 + int(s[j]-'0')
		}
		var vv int
		for j = j + 1; j < len(s); j++ {
			if s[j] == ',' || s[j] == ' ' {
				break
			}
			vv = vv*10 + int(s[j]-'0')
		}
		return expr{tp: exprTypeVariable, x: string(c), v: v, vv: vv}, j - 1, nil
	}
}

func transformS(s string) string {
	items := []cond{}
	var lexpr, rexpr expr
	state := "st"
	oexpr, i, err := parseExpr(s, 0)
	if err != nil {
		panic(err)
	}
	for ; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '=' || s[i] == ',' {
			continue
		}
		switch state {
		case "lt":
			lexpr, i, err = parseExpr(s, i)
			if err != nil {
				panic(err)
			}
			state = "ed"
		case "ed":
			rexpr, i, err = parseExpr(s, i)
			if err != nil {
				panic(err)
			}
			state = "st"
			items = append(items, cond{lexpr, rexpr})
		}
	}
	ss := ""
	for i := 0; i < len(items); i++ {
		ss = fmt.Sprintf("%s ^ %s", ss, items[i])
	}
	return fmt.Sprintf("wmd.%s[%d] = wmd.%s[%d] ^ %s", oexpr.x, oexpr.v, oexpr.x, oexpr.v, ss)
}

func main() {

}
