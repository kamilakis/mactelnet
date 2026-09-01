// SPDX-License-Identifier: GPL-3.0-only

package mt

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// Vectors generated from petrunetworking/MAC-Telnet-Routeros (elliptic_curves.py),
// the reference implementation of this scheme.
func TestPublicKeyMatchesReference(t *testing.T) {
	priv := seq(1, 32)
	pub, parity := PublicKey(priv)
	want := "718f0034ba92aade2eb5495170db6aa13f5d8c29f2c575942eb2d6390788a50a"
	if got := hex.EncodeToString(pub); got != want {
		t.Errorf("public key\n got %s\nwant %s", got, want)
	}
	if parity != 1 {
		t.Errorf("parity = %d, want 1", parity)
	}
}

// The base point is lift_x(9, EVEN), the negation of the usual generator. The
// odd lift is the published Curve25519 base point, which anchors the curve maths
// against a value from outside this project.
func TestBasePointAndKnownCurve25519Generator(t *testing.T) {
	if g := basePoint(); g.y.Bit(0) != 0 {
		t.Error("base point must have even y")
	}
	odd, ok := liftX(big.NewInt(9), 1)
	if !ok {
		t.Fatal("lift_x(9, odd) failed")
	}
	wantY := "20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9"
	if got := hex.EncodeToString(leftPad(odd.y.Bytes(), 32)); got != wantY {
		t.Errorf("lift_x(9,odd).y\n got %s\nwant %s (the published Curve25519 base point y)", got, wantY)
	}
}

func TestValidatorMatchesReference(t *testing.T) {
	salt := seq(0, 16)
	want := "865486414f27943b1e7bdd6a234356c98f01ce4492b447410faaab95bb28a20f"
	if got := hex.EncodeToString(Validator("admin", "secret", salt)); got != want {
		t.Errorf("validator\n got %s\nwant %s", got, want)
	}
}

func TestRedp1MatchesReference(t *testing.T) {
	pub, _ := PublicKey(seq(1, 32))
	x, parity := toMontgomery(redp1(pub, 1))
	want := "4495ec48628d0543dbd8e8d88de9d548eb42044c5f7e377839025adac76976ce"
	if got := hex.EncodeToString(x); got != want {
		t.Errorf("redp1 x\n got %s\nwant %s", got, want)
	}
	if parity != 1 {
		t.Errorf("redp1 parity = %d, want 1", parity)
	}
}

// The whole proof, end to end, for both server parities. The reference client
// mis-slices the parity byte and always takes the odd point; we parse the real
// byte, so both cases must be right.
func TestConfirmationMatchesReference(t *testing.T) {
	priv := seq(1, 32)
	pub, _ := PublicKey(priv)
	salt := seq(0, 16)
	serverPub, _ := hex.DecodeString("13b44beebbf0ab83d27f02353d453339dbd0410948e2fa12570782fe8a4a7337")

	for _, tc := range []struct {
		parity int
		want   string
	}{
		{0, "6e926d674b0680cc9e93f6b2adde0854c459fbfd74b054cf1655d6e81693c479"},
		{1, "f243f58f923219b527e1b9250b2c36fa506975a49944cf805294b8e19cdbb6f7"},
	} {
		got, err := Confirmation("admin", "secret", salt, priv, pub, serverPub, tc.parity)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("confirmation (parity %d)\n got %s\nwant %s", tc.parity, hex.EncodeToString(got), tc.want)
		}
	}
}

// Scalar multiplication is where the PowerShell port broke: a dropped hex digit
// in curve a affected only point doubling, since a appears nowhere else.
func TestScalarMultConsistency(t *testing.T) {
	g := basePoint()
	if got := addPoints(g, g); !sameX(got, scalarMult(big.NewInt(2), g)) {
		t.Error("G+G != 2G")
	}
	a := scalarMult(big.NewInt(7), scalarMult(big.NewInt(6), g))
	b := scalarMult(big.NewInt(42), g)
	if !sameX(a, b) {
		t.Error("7*(6*G) != 42*G")
	}
}

func sameX(a, b point) bool { return !a.inf && !b.inf && a.x.Cmp(b.x) == 0 }

func seq(start, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(start + i)
	}
	return b
}
