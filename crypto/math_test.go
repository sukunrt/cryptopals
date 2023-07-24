package crypto

import (
	"fmt"
	"testing"

	bi "github.com/sukunrt/bigint"
)

func TestPollardKangarooDiscreteLog(t *testing.T) {
	tests := []struct {
		y, a, b, g, p int
	}{
		{y: 10, a: 5, b: 100, g: 2, p: 23},
		{y: 13, a: 10, b: 20, g: 3, p: 101},
		{y: 1234, a: 500, b: 20000, g: 23, p: 189643},
	}
	bii := bi.FromInt
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			target := bi.Exp(bii(tc.g), bii(tc.y), bii(tc.p))
			res, err := PollardKangarooDiscreteLog(target, bii(tc.a), bii(tc.b), bii(tc.g), bii(tc.p))
			if err != nil {
				t.Fatalf("failed %+v: %s\n", tc, err)
			}
			resTarget := bi.Exp(bii(tc.g), res, bii(tc.p))
			if !resTarget.Equal(target) {
				t.Fatalf("failed %+v: got: %d,  want: %d\n", tc, res.Int(), tc.y)
			}
		})
	}
}

func TestPollardKangarooDiscreteLogBig(t *testing.T) {
	p, _ := bi.FromString("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623", 10)
	g, _ := bi.FromString("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357", 10)
	a := bi.Zero
	b := bi.FromInt(1 << 21)
	y, _ := bi.FromString("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119", 10)
	yy, err := PollardKangarooDiscreteLog(y, a, b, g, p)
	if err != nil {
		t.Fatal(err)
	}
	goty := bi.Exp(g, yy, p)
	if !goty.Equal(y) {
		t.Fatalf("didn't get expected y")
	}
}
