package pkg

import (
	"fmt"
	"regexp"
	"strings"
)

type LogEntry struct {
	IP           string
	Timestamp    string
	Method       string
	URL          string
	StatusCode   int
	ResponseSize int
	UserAgent    string
	ResponseTime float64
	Raw          string
}

// Format: IP - - [timestamp] "METHOD URL PROTOCOL" status size "referer" "user-agent"
func ParseLogLine(line string) *LogEntry {
	entry := &LogEntry{Raw: line}

	pattern := `^(\S+) - \S* \[([^\]]+)\] "(\S+) ([^"]*) \S+" (\d+) (\d+|-) "([^"]*)" "([^"]*)"`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(line)

	if len(matches) >= 9 {
		entry.IP = matches[1]
		entry.Timestamp = matches[2]
		entry.Method = matches[3]
		entry.URL = matches[4]

		fmt.Sscanf(matches[5], "%d", &entry.StatusCode)

		if matches[6] != "-" {
			fmt.Sscanf(matches[6], "%d", &entry.ResponseSize)
		}

		entry.UserAgent = matches[8]
	} else {
		ipRegex := regexp.MustCompile(`^(\S+)`)
		if ipMatch := ipRegex.FindStringSubmatch(line); len(ipMatch) > 1 {
			entry.IP = ipMatch[1]
		}
	}

	return entry
}

func IsSuspicious(entry *LogEntry) bool {
	suspiciousPatterns := []string{
		".env", "phpinfo", "eval-stdin", "cgi-bin",
		"shell", "/bin/sh", "wget", "curl",
		"etc/passwd", "cmd=", "exec", "system(",
		"docker", "actuator", ".git", "phpunit",
		"invokefunction", "XDEBUG", "\\x",
	}

	urlLower := strings.ToLower(entry.URL)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(urlLower, pattern) {
			return true
		}
	}

	if strings.Contains(urlLower, "union") || strings.Contains(urlLower, "select") {
		return true
	}

	if strings.Contains(urlLower, "<script") || strings.Contains(urlLower, "javascript:") {
		return true
	}

	return false
}

func IsBot(userAgent string) bool {
	botPatterns := []string{
		"bot", "crawler", "spider", "scraper",
		"Googlebot", "Bytespider", "zgrab",
		"masscan", "censys", "shodan",
	}

	uaLower := strings.ToLower(userAgent)
	for _, pattern := range botPatterns {
		if strings.Contains(uaLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}
