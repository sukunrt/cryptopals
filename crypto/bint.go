package crypto

import "math/big"

type BII struct {
	*big.Int
}

func NBI(i int) BII {
	return BII{big.NewInt(int64(i))}
}

func NBICopy(x BII) BII {
	return BII{big.NewInt(0).Set(x.Int)}
}

func NB() BII {
	return BII{big.NewInt(0)}
}

func Exp(a BII, y BII, n BII) BII {
	return BII{BI(0).Exp(a.Int, y.Int, n.Int)}
}

func (b BII) Mul(x BII) BII {
	return BII{NBI(0).Int.Mul(b.Int, x.Int)}
}

func (b BII) Mod(x BII) BII {
	return BII{NBI(0).Int.Mod(b.Int, x.Int)}
}

func (b BII) Sub(x BII) BII {
	return BII{NBI(0).Int.Sub(b.Int, x.Int)}
}

func (b BII) Div(x BII) BII {
	return BII{NBI(0).Int.Div(b.Int, x.Int)}
}

func (b BII) Equal(x BII) bool {
	return b.Cmp(x.Int) == 0
}
