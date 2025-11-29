package main

import (
	"bufio"
	"exampleProject/pkg"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"time"
)

func GenerateNginxLog(filename string, lines int) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 1<<20) // 1MB buffer
	defer w.Flush()

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"}
	paths := []string{
		"/", "/index.html", "/login", "/logout",
		"/api/items", "/api/items/123", "/search?q=go", "/assets/style.css",
	}
	statuses := []int{200, 201, 204, 301, 302, 400, 401, 403, 404, 500}
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/16.0 Safari/605.1.15",
		"curl/7.68.0",
		"Wget/1.20.3 (linux-gnu)",
		"PostmanRuntime/7.29.0",
	}
	referers := []string{"-", "http://example.com/", "https://google.com/", "https://github.com/"}

	// base time for logs (randomized around now within last 30 days)
	now := time.Now()
	maxOffsetSeconds := int64(30 * 24 * 3600)

	// helper to build IP fast
	makeIP := func() string {
		return strconv.Itoa(r.Intn(256)) + "." +
			strconv.Itoa(r.Intn(256)) + "." +
			strconv.Itoa(r.Intn(256)) + "." +
			strconv.Itoa(r.Intn(256))
	}

	// Format: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 1234 "http://ref" "UA"
	for i := 0; i < lines; i++ {
		ip := makeIP()
		t := now.Add(-time.Duration(r.Int63n(maxOffsetSeconds)) * time.Second)
		timeStr := t.Format("02/Jan/2006:15:04:05 -0700")
		method := methods[r.Intn(len(methods))]
		path := paths[r.Intn(len(paths))]
		status := statuses[r.Intn(len(statuses))]
		size := strconv.Itoa(r.Intn(100000) + 200) // body bytes
		referer := referers[r.Intn(len(referers))]
		ua := userAgents[r.Intn(len(userAgents))]

		// build line without fmt for speed
		line := ip + " - - [" + timeStr + "] \"" +
			method + " " + path + " HTTP/1.1\" " +
			strconv.Itoa(status) + " " + size + " \"" + referer + "\" \"" + ua + "\"\n"

		if _, err := w.WriteString(line); err != nil {
			return err
		}

		// periodic flush to keep buffer size bounded and make progress visible on disk
		if (i+1)%100000 == 0 {
			if err := w.Flush(); err != nil {
				return err
			}
		}
	}

	// final flush done by deferred call
	return nil
}

func main() {
	//filename := "logs_nginx_16_11-25.log"
	filename := "nginx_logs_29_11_2025.log"
	//filename := "big_log.log"
	//GenerateNginxLog(filename, 1000000)
	numWorkers := runtime.NumCPU()
	if numWorkers > 1 {
		numWorkers--
	}

	numWorkers = 10000

	fileInfo, _ := os.Stat(filename)
	fmt.Printf("Розмір файлу: %.2f MB\n\n", float64(fileInfo.Size())/(1024*1024))

	// 1. Sequential
	fmt.Println("=== 1. ПОСЛІДОВНА ОБРОБКА ===")
	t0 := time.Now()
	stats1, _ := pkg.SequentialAnalyze(filename)
	d1 := time.Since(t0)
	pkg.PrintStats(stats1, d1.Milliseconds())

	// 2. Worker Pool
	fmt.Println("\n=== 2. ПАРАЛЕЛЬНА ОБРОБКА (Worker Pool) ===")
	fmt.Printf("Workers: %d\n", numWorkers)
	t0 = time.Now()
	stats2, _ := pkg.ParallelAnalyzeWorkerPool(filename, numWorkers)
	d2 := time.Since(t0)
	pkg.PrintStats(stats2, d2.Milliseconds())
	pkg.PrintSpeedup(d1.Milliseconds(), d2.Milliseconds())

	// 3. Fan-out/Fan-in
	fmt.Println("\n=== 3. FAN-OUT/FAN-IN PATTERN ===")
	fmt.Printf("Workers: %d\n", numWorkers)
	t0 = time.Now()
	stats3, _ := pkg.ParallelAnalyzeFanOut(filename, numWorkers)
	d3 := time.Since(t0)
	pkg.PrintStats(stats3, d3.Milliseconds())
	pkg.PrintSpeedup(d1.Milliseconds(), d3.Milliseconds())

	// 4. Pipeline
	fmt.Println("\n=== 4. PIPELINE PATTERN ===")
	t0 = time.Now()
	stats4, _ := pkg.ParallelAnalyzePipeline(filename)
	d4 := time.Since(t0)
	pkg.PrintStats(stats4, d4.Milliseconds())
	pkg.PrintSpeedup(d1.Milliseconds(), d4.Milliseconds())

	fmt.Println("\n" + string("============================================================"))
	fmt.Println("ПІДСУМОК ПОРІВНЯННЯ")
	fmt.Println("============================================================")
	fmt.Printf("Послідовна:        %v\n", d1)
	fmt.Printf("Worker Pool:       %v (%.2fx швидше)\n", d2, float64(d1)/float64(d2))
	fmt.Printf("Fan-Out/Fan-In:    %v (%.2fx швидше)\n", d3, float64(d1)/float64(d3))
	fmt.Printf("Pipeline:          %v (%.2fx швидше)\n", d4, float64(d1)/float64(d4))
}
