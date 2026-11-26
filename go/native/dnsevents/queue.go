// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package dnsevents

import (
	"sync/atomic"
	"time"

	D "github.com/miekg/dns"
)

const eventQueueCapacity = 64
const historyCapacity = 1000
const uidWait = 25 * time.Millisecond

var uidLookupSlots = make(chan struct{}, 16)

func snapshotAnswers(records []D.RR) []D.RR {
	const maxRecords = 64
	const maxBytes = 8 * 1024
	if len(records) == 0 {
		return nil
	}
	answers := make([]D.RR, 0, min(len(records), maxRecords))
	remaining := maxBytes
	for _, record := range records[:cap(answers)] {
		size := D.Len(record)
		if size > remaining {
			break
		}
		remaining -= size
		answers = append(answers, D.Copy(record))
	}
	return answers
}

// Reserve formatter capacity before copying a response. The publisher and
// subscriber access history under the feed lock, independently of DNS replies.
type eventQueue struct {
	events   chan pendingEvent
	reserved chan struct{}
	done     chan struct{}
	history  []Event
	next     int
}

func newEventQueue() *eventQueue {
	return &eventQueue{
		events:   make(chan pendingEvent, eventQueueCapacity),
		reserved: make(chan struct{}, eventQueueCapacity),
		done:     make(chan struct{}),
		history:  make([]Event, 0, historyCapacity),
	}
}

func (q *eventQueue) reserve() bool {
	select {
	case q.reserved <- struct{}{}:
		return true
	default:
		return false
	}
}

func (q *eventQueue) run(publish func(*eventQueue, Event)) {
	for {
		select {
		case <-q.done:
			return
		case pending := <-q.events:
			event := pending.format()
			<-q.reserved
			if event.UID == nil && pending.lookupUID != nil && HasSubscribers() &&
				q.deferUID(event, pending.lookupUID, publish) {
				continue
			}
			publish(q, event)
		}
	}
}

// Bound the lookup itself, even when its callback outlives the event's deadline.
func (q *eventQueue) deferUID(event Event, lookup func() (uint32, bool), publish func(*eventQueue, Event)) bool {
	select {
	case uidLookupSlots <- struct{}{}:
	default:
		return false
	}
	var published atomic.Bool
	timer := time.AfterFunc(uidWait, func() {
		if published.CompareAndSwap(false, true) {
			publish(q, event)
		}
	})
	go func() {
		defer func() { <-uidLookupSlots }()
		var uid uint32
		var known bool
		if HasSubscribers() && active.Load() == q {
			uid, known = lookup()
		}
		if !published.CompareAndSwap(false, true) {
			return
		}
		timer.Stop()
		if known {
			event.UID = &uid
			event.UIDSource = "socket"
		}
		publish(q, event)
	}()
	return true
}

func (q *eventQueue) remember(event Event) {
	if len(q.history) < historyCapacity {
		q.history = append(q.history, event)
		return
	}
	q.history[q.next] = event
	q.next = (q.next + 1) % historyCapacity
}

func (q *eventQueue) snapshot() []Event {
	history := make([]Event, 0, len(q.history))
	history = append(history, q.history[q.next:]...)
	return append(history, q.history[:q.next]...)
}

func sendLatest(listener chan Event, event Event) {
	select {
	case listener <- event:
	default:
		select {
		case <-listener:
		default:
		}
		listener <- event
	}
}
