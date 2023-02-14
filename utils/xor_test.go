package utils

import "testing"

func TestXorBytes(t *testing.T) {
	a := FromHexString("1c0111001f010100061a024b53535009181c")
	b := FromHexString("686974207468652062756c6c277320657965")
	c := ToHexString(XorBytes(a, b))
	want := "746865206b696420646f6e277420706c6179"
	if want != c {
		t.Fatalf("XorBytes failed")
	}
}

func TestXorRepeatingKey(t *testing.T) {
	a := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
	b := []byte("ICE")
	c := ToHexString(RepeatingKeyXor(a, b))
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if want != c {
		t.Fatalf("RepeatingKeyXor failed")
	}

}

func TestHammingDistance(t *testing.T) {
	a := []byte("this is a test")
	b := []byte("wokka wokka!!!")
	if HammingDistance(a, b) != 37 {
		t.Fatalf("Hamming Distance Failed")
	}
}
