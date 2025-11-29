package pkg

import (
	"bufio"
	"os"
)

func ReadLines(file *os.File) <-chan string {
	out := make(chan string, 1000)

	go func() {
		defer close(out)

		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			out <- scanner.Text()
		}
	}()

	return out
}
