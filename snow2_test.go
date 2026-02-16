// snow2_test.go - Versão corrigida
package snow2

import (
	"bytes"
	"testing"
)

func TestSnow2EncryptDecrypt(t *testing.T) {
	testCases := []struct {
		name string
		key  []byte
		iv   []byte
	}{
		{
			name: "Chave/IV zeros",
			key:  make([]byte, 16),
			iv:   make([]byte, 16),
		},
		{
			name: "Chave/IV sequencial",
			key: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			},
			iv: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			},
		},
		{
			name: "Chave aleatória",
			key: []byte{
				0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
				0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
			},
			iv: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			},
		},
	}

	plaintext := []byte("Hello, SNOW 2.0! This is a test message for encryption and decryption.")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ctx1, err := NewCipher(tc.key, tc.iv)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext := make([]byte, len(plaintext))
			ctx1.XORKeyStream(ciphertext, plaintext)

			// Decrypt with new context
			ctx2, err := NewCipher(tc.key, tc.iv)
			if err != nil {
				t.Fatal(err)
			}
			decrypted := make([]byte, len(ciphertext))
			ctx2.XORKeyStream(decrypted, ciphertext)

			if !bytes.Equal(plaintext, decrypted) {
				t.Error("Encrypt/decrypt failed")
			}
		})
	}
}

func TestSnow2KeyIVDependence(t *testing.T) {
	key1 := make([]byte, 16)
	iv1 := make([]byte, 16)

	key2 := make([]byte, 16)
	key2[0] = 0x01
	iv2 := make([]byte, 16)

	ctx1 := NewSnowCtx(key1)
	ctx1.IVSetup(iv1)
	ks1 := ctx1.Keystream()

	ctx2 := NewSnowCtx(key2)
	ctx2.IVSetup(iv2)
	ks2 := ctx2.Keystream()

	// Verificar se são diferentes
	different := false
	for i := 0; i < 16; i++ {
		if ks1[i] != ks2[i] {
			different = true
			break
		}
	}
	if !different {
		t.Error("Different keys produced same keystream")
	}

	// Testar IV diferente
	iv2[0] = 0x01
	ctx3 := NewSnowCtx(key1)
	ctx3.IVSetup(iv2)
	ks3 := ctx3.Keystream()

	different = false
	for i := 0; i < 16; i++ {
		if ks1[i] != ks3[i] {
			different = true
			break
		}
	}
	if !different {
		t.Error("Different IVs produced same keystream")
	}
}

func TestSnow2MultipleBlocks(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)

	ctx := NewSnowCtx(key)
	ctx.IVSetup(iv)

	ks1 := ctx.Keystream()
	ks2 := ctx.Keystream()
	ks3 := ctx.Keystream()

	// Verificar se os blocos são diferentes entre si
	different := false
	for i := 0; i < 16; i++ {
		if ks1[i] != ks2[i] || ks2[i] != ks3[i] {
			different = true
			break
		}
	}
	if !different {
		t.Error("Keystream blocks are identical")
	}

	// Verificar quantas palavras mudaram
	changes := 0
	for i := 0; i < 16; i++ {
		if ks1[i] != ks2[i] {
			changes++
		}
	}
	t.Logf("Blocos 1 e 2 diferem em %d/16 palavras", changes)
}

func TestSnow2XORKeyStreamEdgeCases(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)

	// Testar vários tamanhos
	sizes := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129}
	failed := 0

	for _, size := range sizes {
		t.Run(formatSize(size), func(t *testing.T) {
			ctx, err := NewCipher(key, iv)
			if err != nil {
				t.Fatal(err)
			}

			if size == 0 {
				// Tamanho zero deve funcionar sem panic
				dst := make([]byte, 0)
				src := make([]byte, 0)
				ctx.XORKeyStream(dst, src)
				return
			}

			plaintext := make([]byte, size)
			for i := range plaintext {
				plaintext[i] = byte(i)
			}

			ciphertext := make([]byte, size)
			ctx.XORKeyStream(ciphertext, plaintext)

			// Decrypt with NEW context (same key/IV)
			ctx2, _ := NewCipher(key, iv)
			decrypted := make([]byte, size)
			ctx2.XORKeyStream(decrypted, ciphertext)

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Failed for size %d", size)
				failed++

				// Mostrar detalhes para depuração
				t.Logf("Primeiros bytes:")
				for j := 0; j < size && j < 8; j++ {
					t.Logf("  [%d]: plain=0x%02x, cipher=0x%02x, dec=0x%02x",
						j, plaintext[j], ciphertext[j], decrypted[j])
				}
			}
		})
	}

	if failed > 0 {
		t.Errorf("%d testes falharam", failed)
	}
}

func formatSize(size int) string {
	if size < 1024 {
		return string(rune(size)) + "B"
	} else if size < 1024*1024 {
		return string(rune(size/1024)) + "KB"
	}
	return string(rune(size/(1024*1024))) + "MB"
}

func TestSnow2InvalidParameters(t *testing.T) {
	// Tamanho de chave inválido
	key := make([]byte, 24) // 192 bits não suportado
	iv := make([]byte, 16)

	_, err := NewCipher(key, iv)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}

	// Tamanho de IV inválido
	key = make([]byte, 16)
	iv = make([]byte, 8)

	_, err = NewCipher(key, iv)
	if err == nil {
		t.Error("Expected error for invalid IV size")
	}

	// IV maior que 16
	iv = make([]byte, 32)
	_, err = NewCipher(key, iv)
	if err == nil {
		t.Error("Expected error for IV size > 16")
	}
}

func TestSnow2Deterministic(t *testing.T) {
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	iv := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}

	ctx1 := NewSnowCtx(key)
	ctx1.IVSetup(iv)
	ks1 := ctx1.Keystream()

	ctx2 := NewSnowCtx(key)
	ctx2.IVSetup(iv)
	ks2 := ctx2.Keystream()

	for i := 0; i < 16; i++ {
		if ks1[i] != ks2[i] {
			t.Errorf("Keystream mismatch at word %d: 0x%08x vs 0x%08x",
				i, ks1[i], ks2[i])
		}
	}
}

func TestSnow2NonZeroKey(t *testing.T) {
	key := []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}
	iv := make([]byte, 16)

	ctx := NewSnowCtx(key)
	ctx.IVSetup(iv)

	ks := ctx.Keystream()
	t.Logf("Primeira palavra do keystream: 0x%08x", ks[0])
}

func BenchmarkSnow2Keystream(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 16)

	ctx := NewSnowCtx(key)
	ctx.IVSetup(iv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Keystream()
	}
}

func BenchmarkSnow2XORKeyStream(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 16)

	ctx, _ := NewCipher(key, iv)

	sizes := []int{64, 256, 1024, 4096, 16384}
	for _, size := range sizes {
		b.Run(formatSize(size), func(b *testing.B) {
			data := make([]byte, size)
			dst := make([]byte, size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ctx.XORKeyStream(dst, data)
			}
		})
	}
}
