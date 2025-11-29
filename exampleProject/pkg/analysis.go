package pkg

import (
	"bufio"
	"os"
	"sync"
)

// SequentialAnalyze performs a single-threaded analysis of the log file
func SequentialAnalyze(filename string) (*Statistics, error) {
	file, err := os.Open(filename)
	if err != nil {
		return NewStatistics(), err
	}
	defer file.Close()

	statsObj := NewStatistics()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		entry := ParseLogLine(line)

		statsObj.TotalLines++

		switch {
		case entry.StatusCode >= 200 && entry.StatusCode < 300:
			statsObj.Status2xx++
		case entry.StatusCode >= 300 && entry.StatusCode < 400:
			statsObj.Status3xx++
		case entry.StatusCode >= 400 && entry.StatusCode < 500:
			statsObj.Status4xx++
		case entry.StatusCode >= 500 && entry.StatusCode < 600:
			statsObj.Status5xx++
		}

		if entry.IP != "" {
			statsObj.UniqueIPs[entry.IP]++
		}

		if entry.URL != "" {
			statsObj.URLAccess[entry.URL]++
		}

		if entry.Method != "" {
			statsObj.MethodCount[entry.Method]++
		}

		if IsSuspicious(entry) {
			statsObj.SuspiciousRequest++
		}

		if IsBot(entry.UserAgent) {
			statsObj.BotRequests++
		}
	}

	return statsObj, nil
}

// ParallelAnalyzeWorkerPool runs a worker-pool based parallel analysis
func ParallelAnalyzeWorkerPool(filename string, numWorkers int) (*Statistics, error) {
	file, err := os.Open(filename)
	if err != nil {
		return NewStatistics(), err
	}
	defer file.Close()

	lineChan := make(chan string, 1000)
	statsChan := make(chan *Statistics, numWorkers)

	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := NewStatistics()
			for line := range lineChan {
				entry := ParseLogLine(line)

				local.TotalLines++

				switch {
				case entry.StatusCode >= 200 && entry.StatusCode < 300:
					local.Status2xx++
				case entry.StatusCode >= 300 && entry.StatusCode < 400:
					local.Status3xx++
				case entry.StatusCode >= 400 && entry.StatusCode < 500:
					local.Status4xx++
				case entry.StatusCode >= 500 && entry.StatusCode < 600:
					local.Status5xx++
				}

				if entry.IP != "" {
					local.UniqueIPs[entry.IP]++
				}

				if entry.URL != "" {
					local.URLAccess[entry.URL]++
				}

				if entry.Method != "" {
					local.MethodCount[entry.Method]++
				}

				if IsSuspicious(entry) {
					local.SuspiciousRequest++
				}

				if IsBot(entry.UserAgent) {
					local.BotRequests++
				}
			}

			statsChan <- local
		}()
	}

	// Reader goroutine
	go func() {
		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			lineChan <- scanner.Text()
		}
		close(lineChan)
	}()

	// Close statsChan when workers done
	go func() {
		wg.Wait()
		close(statsChan)
	}()

	final := NewStatistics()
	for s := range statsChan {
		final.Merge(s)
	}

	return final, nil
}

// fan-out/fan-in pattern
func ParallelAnalyzeFanOut(filename string, numWorkers int) (*Statistics, error) {
	file, err := os.Open(filename)
	if err != nil {
		return NewStatistics(), err
	}
	defer file.Close()

	lines := ReadLines(file)

	workerChannels := make([]<-chan *Statistics, numWorkers)
	for i := 0; i < numWorkers; i++ {
		workerChannels[i] = processLines(lines)
	}

	final := fanIn(workerChannels)
	return final, nil
}

func processLines(lines <-chan string) <-chan *Statistics {
	out := make(chan *Statistics)
	go func() {
		defer close(out)
		local := NewStatistics()
		for line := range lines {
			entry := ParseLogLine(line)
			local.TotalLines++

			switch {
			case entry.StatusCode >= 200 && entry.StatusCode < 300:
				local.Status2xx++
			case entry.StatusCode >= 300 && entry.StatusCode < 400:
				local.Status3xx++
			case entry.StatusCode >= 400 && entry.StatusCode < 500:
				local.Status4xx++
			case entry.StatusCode >= 500 && entry.StatusCode < 600:
				local.Status5xx++
			}

			if entry.IP != "" {
				local.UniqueIPs[entry.IP]++
			}

			if entry.URL != "" {
				local.URLAccess[entry.URL]++
			}

			if entry.Method != "" {
				local.MethodCount[entry.Method]++
			}

			if IsSuspicious(entry) {
				local.SuspiciousRequest++
			}

			if IsBot(entry.UserAgent) {
				local.BotRequests++
			}
		}

		out <- local
	}()
	return out
}

func fanIn(channels []<-chan *Statistics) *Statistics {
	final := NewStatistics()
	var wg sync.WaitGroup
	for _, c := range channels {
		wg.Add(1)
		go func(ch <-chan *Statistics) {
			defer wg.Done()
			for s := range ch {
				final.Merge(s)
			}
		}(c)
	}
	wg.Wait()
	return final
}

// Pipeline-style analysis
func ParallelAnalyzePipeline(filename string) (*Statistics, error) {
	file, err := os.Open(filename)
	if err != nil {
		return NewStatistics(), err
	}
	defer file.Close()

	lines := ReadLines(file)
	parsed := parseStage(lines, 4)
	analyzed := analyzeStage(parsed, 4)
	final := aggregateStage(analyzed)
	return final, nil
}

func parseStage(lines <-chan string, workers int) <-chan *LogEntry {
	out := make(chan *LogEntry, 1000)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range lines {
				out <- ParseLogLine(line)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func analyzeStage(entries <-chan *LogEntry, workers int) <-chan *Statistics {
	out := make(chan *Statistics, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := NewStatistics()
			count := 0
			for entry := range entries {
				local.TotalLines++
				switch {
				case entry.StatusCode >= 200 && entry.StatusCode < 300:
					local.Status2xx++
				case entry.StatusCode >= 300 && entry.StatusCode < 400:
					local.Status3xx++
				case entry.StatusCode >= 400 && entry.StatusCode < 500:
					local.Status4xx++
				case entry.StatusCode >= 500 && entry.StatusCode < 600:
					local.Status5xx++
				}

				if entry.IP != "" {
					local.UniqueIPs[entry.IP]++
				}

				if entry.URL != "" {
					local.URLAccess[entry.URL]++
				}

				if entry.Method != "" {
					local.MethodCount[entry.Method]++
				}

				if IsSuspicious(entry) {
					local.SuspiciousRequest++
				}

				if IsBot(entry.UserAgent) {
					local.BotRequests++
				}

				count++
				if count%1000 == 0 {
					out <- local
					local = NewStatistics()
				}
			}

			if local.TotalLines > 0 {
				out <- local
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func aggregateStage(statsStream <-chan *Statistics) *Statistics {
	final := NewStatistics()
	for s := range statsStream {
		final.Merge(s)
	}
	return final
}
