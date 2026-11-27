// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package dnsevents

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	D "github.com/miekg/dns"
)

const Path = "/asterisk/dns-events"

type answer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	Data string `json:"data"`
}

type Event struct {
	Seq          uint64    `json:"seq"`
	Time         int64     `json:"time"`
	Delay        int64     `json:"delay"`
	Qname        string    `json:"qname"`
	Qtype        uint16    `json:"qtype"`
	Status       string    `json:"status"`
	Rcode        *int      `json:"rcode,omitempty"`
	Answers      *[]answer `json:"answers,omitempty"`
	AnswerSource string    `json:"answerSource,omitempty"`
	Upstream     string    `json:"upstream,omitempty"`
	Route        string    `json:"route,omitempty"`
	OutboundTag  string    `json:"outboundTag,omitempty"`
	UID          *uint32   `json:"uid,omitempty"`
	UIDSource    string    `json:"uidSource,omitempty"`
}

type pendingEvent struct {
	Event
	wireAnswers []D.RR
	origin      Origin
	lookupUID   func() (uint32, bool)
}

func (e pendingEvent) format() Event {
	if e.Rcode != nil {
		answers := make([]answer, 0, len(e.wireAnswers))
		for _, record := range e.wireAnswers {
			header := record.Header()
			data := answerData(record)
			answers = append(answers, answer{Name: header.Name, Type: header.Rrtype, Data: data})
		}
		e.Answers = &answers
	}
	e.Upstream = e.origin.upstreamAddress()
	if e.UID != nil {
		e.UIDSource = "socket"
	}
	return e.Event
}

func answerData(record D.RR) string {
	switch record := record.(type) {
	case *D.A:
		if record.A == nil {
			return ""
		}
		return record.A.String()
	case *D.AAAA:
		if record.AAAA == nil {
			return ""
		}
		if record.AAAA.To4() != nil {
			return "::ffff:" + record.AAAA.String()
		}
		return record.AAAA.String()
	case *D.TXT:
		if len(record.Txt) == 1 && isPlainTXT(record.Txt[0]) {
			return "\"" + record.Txt[0] + "\""
		}
	}
	return strings.TrimSpace(strings.TrimPrefix(record.String(), record.Header().String()))
}

func isPlainTXT(text string) bool {
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c < ' ' || c > '~' || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

type Origin struct {
	Source         string
	Upstream       interface{ Address() string }
	UpstreamScheme string
	Egress
}

type Egress struct {
	Route, OutboundTag string
}

type requestKey struct{}
type uidKey struct{}

type uidLookupKey struct{}

type egressKey struct{}

type Observation struct {
	start     time.Time
	origin    Origin
	uid       *uint32
	queue     *eventQueue
	lookupUID func() (uint32, bool)
}

var active atomic.Pointer[eventQueue]
var subscribed atomic.Bool
var stream = struct {
	sync.Mutex
	seq       uint64
	listeners map[chan Event]struct{}
}{listeners: make(map[chan Event]struct{})}

func Enabled() bool { return active.Load() != nil }

func HasSubscribers() bool { return subscribed.Load() }

func StartCollection() {
	stream.Lock()
	defer stream.Unlock()
	if active.Load() == nil {
		queue := newEventQueue()
		active.Store(queue)
		go queue.run(publish)
	}
}

func StopCollection() {
	stream.Lock()
	defer stream.Unlock()
	if queue := active.Swap(nil); queue != nil {
		close(queue.done)
	}
	for listener := range stream.listeners {
		close(listener)
	}
	clear(stream.listeners)
	subscribed.Store(false)
}

func Subscribe() ([]Event, <-chan Event, func(), bool) {
	stream.Lock()
	defer stream.Unlock()
	queue := active.Load()
	if queue == nil {
		return nil, nil, nil, false
	}
	listener := make(chan Event, eventQueueCapacity)
	stream.listeners[listener] = struct{}{}
	subscribed.Store(true)
	return queue.snapshot(), listener, func() {
		stream.Lock()
		delete(stream.listeners, listener)
		subscribed.Store(len(stream.listeners) != 0)
		stream.Unlock()
	}, true
}

func WithUID(ctx context.Context, uid uint32) context.Context {
	return context.WithValue(ctx, uidKey{}, uid)
}

func WithUIDLookup(ctx context.Context, lookup func() (uint32, bool)) context.Context {
	return context.WithValue(ctx, uidLookupKey{}, lookup)
}

func Start(ctx context.Context, query *D.Msg) (context.Context, *Observation) {
	queue := active.Load()
	if queue == nil || len(query.Question) == 0 || query.Response || query.Opcode != D.OpcodeQuery {
		return ctx, nil
	}
	o := &Observation{start: time.Now(), queue: queue}
	if uid, ok := ctx.Value(uidKey{}).(uint32); ok {
		o.uid = &uid
	} else if lookup, ok := ctx.Value(uidLookupKey{}).(func() (uint32, bool)); ok {
		o.lookupUID = lookup
	}
	return context.WithValue(ctx, requestKey{}, o), o
}

func SetOrigin(ctx context.Context, origin Origin) {
	if !Enabled() {
		return
	}
	if o, ok := ctx.Value(requestKey{}).(*Observation); ok {
		o.origin = origin
	}
}

func SourceIfUnknown(ctx context.Context, source string) {
	if !Enabled() {
		return
	}
	if o, ok := ctx.Value(requestKey{}).(*Observation); ok && o.origin.Source == "" {
		o.origin.Source = source
	}
}

func TrackEgress(ctx context.Context) (context.Context, *atomic.Pointer[Egress]) {
	info := new(atomic.Pointer[Egress])
	return context.WithValue(ctx, egressKey{}, info), info
}

func TrackingEgress(ctx context.Context) bool {
	return Enabled() && ctx.Value(egressKey{}) != nil
}

func SetEgress(ctx context.Context, route, tag string) {
	if !Enabled() {
		return
	}
	if info, ok := ctx.Value(egressKey{}).(*atomic.Pointer[Egress]); ok {
		info.Store(&Egress{Route: route, OutboundTag: tag})
	}
}

func (o *Observation) Finish(query *D.Msg, response *D.Msg, err error) {
	if o == nil || active.Load() != o.queue || !o.queue.reserve() {
		return
	}
	now := time.Now()
	q := query.Question[0]
	event := pendingEvent{
		Event: Event{
			Time: now.UnixMilli(), Delay: now.Sub(o.start).Milliseconds(),
			Qname: q.Name, Qtype: q.Qtype, Status: "failed", UID: o.uid,
			AnswerSource: o.origin.Source, Route: o.origin.Route, OutboundTag: o.origin.OutboundTag,
		},
		origin:    o.origin,
		lookupUID: o.lookupUID,
	}
	if response != nil {
		event.Status = "answered"
		rcode := response.Rcode
		event.Rcode = &rcode
		event.wireAnswers = snapshotAnswers(response.Answer)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		event.Status = "timeout"
	}
	o.queue.events <- event
}

func publish(queue *eventQueue, event Event) {
	stream.Lock()
	defer stream.Unlock()
	if active.Load() != queue {
		return
	}
	stream.seq++
	event.Seq = stream.seq
	queue.remember(event)
	for listener := range stream.listeners {
		sendLatest(listener, event)
	}
}

func (o Origin) upstreamAddress() string {
	if o.Upstream == nil {
		return ""
	}
	address := o.Upstream.Address()
	if o.UpstreamScheme != "" {
		address = o.UpstreamScheme + "://" + address
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" || strings.Contains(parsed.Host, ",") {
		return ""
	}
	switch parsed.Scheme {
	case "udp", "tcp", "tls", "https", "quic":
		return parsed.Scheme + "://" + parsed.Host
	default:
		return ""
	}
}
