package csidh

import (
	"testing"
	//        mrand "math/rand"
)

var skip bool = false

/*
func TestXMulHardcodedCase1(t *testing.T) {
	if skip {
		t.Skip()
	}
	var k = Fp{0xc5fb0e4f9e9ab465, 0x8f274f2a0e996697, 0x85e355bf54b522df, 0x70224, 0x0, 0x0, 0x0, 0x0}
	var co = Coeff{
		a: Fp{0x636628b1f75a40cb, 0x9b505caedce224e3, 0x3af4240a2e565cc9, 0x2cfe5a6ee8be0492, 0xab3c305d60f62cf3, 0x715c848c113fc81c, 0x33dfa3bb7a59879f, 0xa6ba5983316edc0},
		c: Fp{0xc8fc8df598726f0a, 0x7b1bc81750a6af95, 0x5d319e67c1e961b4, 0xb0aa7275301955f1, 0x4a080672d9ba6c64, 0x97a5ef8a246ee77b, 0x6ea9e5d4383676a, 0x3496e2e117e0ec80},
	}
	var p = Point{
		x: Fp{0x55a43672ef5db01a, 0xb0e2d4dcce364210, 0xb28c9196b1ca2774, 0x57f7fc16252bce09, 0x66d11b31ef77e754, 0x9615a7a0173ffa43, 0xc7770143d5a11038, 0xfaafc2a4ade2ef9},
		z: Fp{0x91efc95a5bb54125, 0x75bce0b0215c76e4, 0xe56bc397348c872, 0xb8fe66488b4273b8, 0xe94387a4465b9abc, 0x2090583fd87d0f29, 0xfb9f455f1e93484c, 0x287d75a20c187792},
	}
	var expQ = Point{
		x: Fp{0xa13c1eea6cfb5097, 0xf1cc3da11b190fb9, 0x7ffcf4ac2e0bcff8, 0xbc281fb7da094dda, 0x30af6810bab7f72a, 0xb472670a51db8f7f, 0xb058aad7febb2157, 0x2df39b6b7a0ab2ec},
		z: Fp{0xda7de079b9ddd589, 0xf1cb061aaf885997, 0x9c92ee6e676cba62, 0x3c506b68a98f1a6b, 0xc30ee80d81b43c5e, 0xf630520094753c54, 0x270a06de1166db23, 0x3a18486a1d64f9f3},
	}
	var Q Point

	xMul512(&Q, &p, &co, &k)
	if !Q.x.Equals(&expQ.x) || !Q.z.Equals(&expQ.z) {
		t.Errorf("Wrong result")
	}
}
*/
func TestXDBLADDHardcodedCase1(t *testing.T) {
	var Qout, Pout Point
	var A24 Coeff

	var Qin = Point{
		x: Fp{1761179198795014244, 15957558271466463395, 17204248159906018085, 13916412413803281, 5808659586597314978, 29670788488173325, 5625261851677878218, 6626031831900646802},
		z: Fp{16354694537241826533, 5301208672305966941, 11868746402605886127, 11160200437071073996, 6287806084527778519, 5968727642232544773, 2793897677713259413, 4539817052475923222},
	}
	var Pin = Point{
		x: Fp{0xbce1b716c70d3d7c, 0x93f9eafc157f9f81, 0xe6df8f37ff564712, 0x27bf8cf4942ac978, 0x813ea64a09fc97c5, 0x15be9657c255816a, 0x9d12ace19ee5664c, 0x14671dba1a8e55cd},
		z: Fp{0xaea2c07af8b26a6b, 0x212d6d049fff3d03, 0x73bd25b62ddad873, 0x1e9e2c6ebd0f0d5, 0xbcf704c743bf3aa, 0xc7374699fe3bff95, 0xac438fafa529ad5a, 0x9958440d71d3b68},
	}
	var Pcopy = Point{
		x: Fp{0xa167306048ddc177, 0x199093d6fe41168c, 0x4b04db18ac6e5ae2, 0xdf4c88b377ad4ada, 0xcf09d445575a8c4b, 0x8957ec156cb25ba3, 0x7d944a2beb274eef, 0x4a7319885f705ee2},
		z: Fp{0xe40cbeb30271f95e, 0x1a4cb1a86be5ca83, 0x885b7c6d8564bac0, 0xb34bbfc4bbdf3713, 0xae8fcb2f9986299a, 0x8f7c6b22f33c7dd7, 0xfc24a261445594d6, 0x52f1564f914aeb1},
	}
	var A = Coeff{
		a: Fp{0x636628b1f75a40cb, 0x9b505caedce224e3, 0x3af4240a2e565cc9, 0x2cfe5a6ee8be0492, 0xab3c305d60f62cf3, 0x715c848c113fc81c, 0x33dfa3bb7a59879f, 0xa6ba5983316edc0},
		c: Fp{0xc8fc8df598726f0a, 0x7b1bc81750a6af95, 0x5d319e67c1e961b4, 0xb0aa7275301955f1, 0x4a080672d9ba6c64, 0x97a5ef8a246ee77b, 0x6ea9e5d4383676a, 0x3496e2e117e0ec80},
	}

	// Precompyte A24 = (A+2C:4C) => (A24.x = A.x+2A.z; A24.z = 4*A.z)
	addRdc(&A24.a, &A.c, &A.c)
	addRdc(&A24.a, &A24.a, &A.a)
	mulRdc(&A24.c, &A.c, &four)

	// A24 is used when calculating Qout only
	xDblAdd(&Qin, &Pin, &Qin, &Pin, &Pcopy, &A24)

	Qout = Qin
	Pout = Pin

	var QoutExp = Point{
		x: Fp{0x3e5df27f6d643a38, 0x54aef929d2f14dec, 0x4d41b116cc8c4f79, 0xfd615127e75faf03, 0x1adf9acd519fe139, 0xb83f44aa8acd6399, 0xed5d73d9c7d71099, 0x535451697a134ecb},
		z: Fp{0xc4c66c4403f0c2e0, 0x55d50bf24e9798a1, 0x7bcde89b55affc35, 0xe87daa68226c8d82, 0x7ee9118a524119ed, 0xd41a199e0b40c1d3, 0xb352b8916db366f3, 0x1c92e7d5c6dabd6e},
	}
	var PoutExp = Point{
		x: Fp{0xa08ae21ef8702f77, 0xf4f7c359129929bd, 0x34b335493bb1729, 0x3007ad767cd75b47, 0x6a4dfaf129ec0508, 0xd07b73634100a766, 0xd35a5c575ed04890, 0x5b9807c796bbc8a3},
		z: Fp{0x5ad509dbda78efe8, 0xff68677d954e2045, 0xa275d0e966c3bf88, 0x2c9dc76383abc11b, 0x54c4e00ad6f8e008, 0x11f79701a670f718, 0xf3a43f8dfe5ed38d, 0x500f7a639c72227c},
	}

	if !PoutExp.x.Equals(&Pout.x) || !PoutExp.z.Equals(&Pout.z) {
		t.Errorf("Wrong P: \n%X\n%X\n", Pout.x, Pout.z)
	}
	if !QoutExp.x.Equals(&Qout.x) || !QoutExp.z.Equals(&Qout.z) {
		t.Errorf("Wrong Q: \n%X\n%X\n", Qout.x, Qout.z)
	}
}

func TestVerificationQuicky(t *testing.T) {
	if skip {
		t.Skip()
	}
	var pub PublicKey
	/*
	   pub.A = two
	   if pub.Validate() {
	     t.Error("A should be invalid")
	   }
	   pPlus1 := p
	   pPlus1[0] += 1
	   pub.A = pPlus1
	   if pub.Validate() {
	     t.Error("A should be invalid")
	   }
	   // A==0 is actualy supersingular
	   pub.A = Fp{}
	   if !pub.Validate() {
	     t.Error("A should be valid")
	   }
	   // A==1
	   pub.A = fp_1
	   if pub.Validate() {
	     t.Error("A should be invalid")
	   }
	*/
	// A==6
	pub.A = Fp{
		0x636628B1F75A40CB,
		0x9B505CAEDCE224E3,
		0x3AF4240A2E565CC9,
		0x2CFE5A6EE8BE0492,
		0xAB3C305D60F62CF3,
		0x715C848C113FC81C,
		0x33DFA3BB7A59879F,
		0x0A6BA5983316EDC0,
	}
	if !pub.Validate() {
		t.Error("A should be valid")
	}
	/*
	   // A==4908
	   pub.A = Fp{
	     0xB15F0BF894F008C5,
	     0x3BC916855D9F555B,
	     0xFBA65659FF49D2F4,
	     0x685E8462FB4609E0,
	     0xA69F95FE1E543358,
	     0xCF05DC7405C7F217,
	     0xDFA1D92B63E09F3F,
	     0x526CE7D09E3A06E6,
	   }
	   if pub.Validate() {
	     t.Error("A should be invalid")
	   }
	*/
}
