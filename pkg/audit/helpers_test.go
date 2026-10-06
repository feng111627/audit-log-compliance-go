package audit

import "time"

func parseTestTime(seq int64) time.Time {
	return time.Date(2026, 10, 6, 10, 0, int(seq%60), 0, time.UTC)
}
