package pkg

import "sync"

type Statistics struct {
	TotalLines        int
	Status2xx         int
	Status3xx         int
	Status4xx         int
	Status5xx         int
	UniqueIPs         map[string]int
	URLAccess         map[string]int
	MethodCount       map[string]int
	SuspiciousRequest int
	BotRequests       int
	mu                sync.Mutex
}

func NewStatistics() *Statistics {
	return &Statistics{
		UniqueIPs:   make(map[string]int),
		URLAccess:   make(map[string]int),
		MethodCount: make(map[string]int),
	}
}

func (s *Statistics) Merge(other *Statistics) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalLines += other.TotalLines
	s.Status2xx += other.Status2xx
	s.Status3xx += other.Status3xx
	s.Status4xx += other.Status4xx
	s.Status5xx += other.Status5xx
	s.SuspiciousRequest += other.SuspiciousRequest
	s.BotRequests += other.BotRequests

	for ip, count := range other.UniqueIPs {
		s.UniqueIPs[ip] += count
	}

	for url, count := range other.URLAccess {
		s.URLAccess[url] += count
	}

	for method, count := range other.MethodCount {
		s.MethodCount[method] += count
	}
}
