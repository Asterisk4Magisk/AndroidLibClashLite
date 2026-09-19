package libclash

import (
	"errors"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/log"
)

// LogcatInterface receives JSON events. Return false to unsubscribe.
type LogcatInterface interface{ Received(payload string) bool }

// LogSubscription allows releasing the callback even when no log events arrive.
type LogSubscription struct {
	once sync.Once
	done chan struct{}
}

// Close is nonblocking and safe to call from Received.
func (s *LogSubscription) Close() { s.once.Do(func() { close(s.done) }) }

func SubscribeLogcat(callback LogcatInterface) (*LogSubscription, error) {
	if callback == nil {
		return nil, errors.New("log callback is required")
	}
	s := &LogSubscription{done: make(chan struct{})}
	sub := log.Subscribe()
	go func() {
		defer log.UnSubscribe(sub)
		defer s.Close()
		for {
			select {
			case <-s.done:
				return
			case msg, ok := <-sub:
				if !ok {
					return
				}
				if msg.LogLevel < log.Level() && !strings.HasPrefix(msg.Payload, "[APP]") {
					continue
				}
				payload := marshalJSON(struct {
					Level   string `json:"level"`
					Message string `json:"message"`
					Time    int64  `json:"time"`
				}{msg.LogLevel.String(), msg.Payload, msg.Time.UnixMilli()})
				if !callback.Received(payload) {
					return
				}
			}
		}
	}()
	return s, nil
}
