package crypto

import (
	"io"
	"os"
	"strings"
)

func ReadFile(filePath string) string {
	f, e := os.Open(filePath)

	if e != nil {
		panic(e)
	}

	defer f.Close()

	b := new(strings.Builder)
	io.Copy(b, f)

	return b.String()
}
