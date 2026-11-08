package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
	"testing"
)

// Renders qrBlock's output (each character a 1×2 cell of half-blocks) to a
// PNG, so a real QR reader can check what the terminal would show.
func TestQRBlockRenders(t *testing.T) {
	out := os.Getenv("QR_PNG")
	if out == "" {
		t.Skip("set QR_PNG=path")
	}
	text := "tekkoh-link:1:abcdefghijklmnopqrstuv:ja_P7q6QRe6aeNeKmfzzLneB5EHrBzCWw0K44tzDthI:agent"
	block, err := qrBlock(text)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, l := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
		l = strings.TrimPrefix(l, "\x1b[30;47m")
		l = strings.TrimSuffix(l, "\x1b[0m")
		rows = append(rows, l)
	}
	const px = 8
	w := len([]rune(rows[0]))
	img := image.NewGray(image.Rect(0, 0, (w+8)*px, (len(rows)*2+8)*px))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	for y, r := range rows {
		for x, ch := range []rune(r) {
			top := ch == '█' || ch == '▀'
			bottom := ch == '█' || ch == '▄'
			for dy := 0; dy < px; dy++ {
				for dx := 0; dx < px; dx++ {
					if top {
						img.Set((x+4)*px+dx, (y*2+4)*px+dy, color.Black)
					}
					if bottom {
						img.Set((x+4)*px+dx, (y*2+5)*px+dy, color.Black)
					}
				}
			}
		}
	}
	f, _ := os.Create(out)
	defer f.Close()
	png.Encode(f, img)
}
