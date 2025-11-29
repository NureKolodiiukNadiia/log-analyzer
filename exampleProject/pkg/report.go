package pkg

import (
	"fmt"
)

func Percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

type keyValue struct {
	key   string
	value int
}

func getTopN(m map[string]int, n int) []keyValue {
	items := make([]keyValue, 0, len(m))
	for k, v := range m {
		items = append(items, keyValue{k, v})
	}

	for i := 0; i < len(items) && i < n; i++ {
		maxIdx := i
		for j := i + 1; j < len(items); j++ {
			if items[j].value > items[maxIdx].value {
				maxIdx = j
			}
		}
		items[i], items[maxIdx] = items[maxIdx], items[i]
	}

	if len(items) > n {
		return items[:n]
	}
	return items
}

func PrintStats(statsObj *Statistics, durationMs int64) {
	fmt.Printf("Час виконання: %d ms\n", durationMs)
	fmt.Printf("Всього рядків: %d\n", statsObj.TotalLines)

	fmt.Printf("\nСтатус коди:\n")
	fmt.Printf("  2xx (OK):       %d (%.2f%%)\n", statsObj.Status2xx, Percent(statsObj.Status2xx, statsObj.TotalLines))
	fmt.Printf("  3xx (Redirect): %d (%.2f%%)\n", statsObj.Status3xx, Percent(statsObj.Status3xx, statsObj.TotalLines))
	fmt.Printf("  4xx (Error):    %d (%.2f%%)\n", statsObj.Status4xx, Percent(statsObj.Status4xx, statsObj.TotalLines))
	fmt.Printf("  5xx (Server):   %d (%.2f%%)\n", statsObj.Status5xx, Percent(statsObj.Status5xx, statsObj.TotalLines))

	fmt.Printf("\nБезпека:\n")
	fmt.Printf("  Підозрілі запити: %d (%.2f%%)\n", statsObj.SuspiciousRequest, Percent(statsObj.SuspiciousRequest, statsObj.TotalLines))
	fmt.Printf("  Запити від ботів: %d (%.2f%%)\n", statsObj.BotRequests, Percent(statsObj.BotRequests, statsObj.TotalLines))

	fmt.Printf("\nУнікальних IP: %d\n", len(statsObj.UniqueIPs))

	fmt.Println("\nТоп-20 найактивніших IP адрес:")
	topIPs := getTopN(statsObj.UniqueIPs, 20)
	for i, item := range topIPs {
		fmt.Printf("  %d. %s: %d запитів (%.2f%%)\n", i+1, item.key, item.value, Percent(item.value, statsObj.TotalLines))
	}

	fmt.Println("\nТоп-10 найбільш запитуваних URL:")
	topURLs := getTopN(statsObj.URLAccess, 10)
	for i, item := range topURLs {
		fmt.Printf("  %d. %s: %d запитів\n", i+1, item.key, item.value)
	}

	fmt.Println("\nHTTP методи:")
	for method, count := range statsObj.MethodCount {
		fmt.Printf("  %s: %d (%.2f%%)\n", method, count, Percent(count, statsObj.TotalLines))
	}
}

func PrintSpeedup(baselineMs, currentMs int64) {
	speedup := float64(baselineMs) / float64(currentMs)
	fmt.Printf("Прискорення: %.2fx\n", speedup)
}
