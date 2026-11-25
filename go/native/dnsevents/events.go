// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package dnsevents

import (
	"context"
	"errors"
	"net/netip"
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
	wireAnswers  []D.RR
	origin       Origin
	lookupUID    func() (uint32, bool)
}

func (e Event) format() Event {
	if e.Rcode != nil {
		answers := make([]answer, 0, len(e.wireAnswers))
		for _, record := range e.wireAnswers {
			header := record.Header()
			data := strings.TrimSpace(strings.TrimPrefix(record.String(), header.String()))
			answers = append(answers, answer{Name: header.Name, Type: header.Rrtype, Data: data})
		}
		e.Answers = &answers
	}
	e.Upstream = e.origin.upstreamAddress()
	if e.UID == nil && e.lookupUID != nil {
		if uid, ok := e.lookupUID(); ok {
			e.UID = &uid
			e.UIDSource = "socket"
		}
	}
	e.wireAnswers = nil
	e.origin = Origin{}
	e.lookupUID = nil
	return e
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

type observedUID struct {
	uid    uint32
	source string
}
type uidLookupKey struct{}
type ingressKey struct{}

type ingress struct {
	network             string
	source, destination netip.AddrPort
}

func WithIngress(ctx context.Context, network string, source, destination netip.AddrPort) context.Context {
	return context.WithValue(ctx, ingressKey{}, ingress{network, source, destination})
}

func WithEnhancedUID(ctx context.Context, request []byte) context.Context {
	if flow, ok := ctx.Value(ingressKey{}).(ingress); ok {
		if uid, found := EnhancedUID(flow.network, flow.source, flow.destination, request); found {
			return context.WithValue(ctx, uidKey{}, observedUID{uid, "enhance"})
		}
	}
	return ctx
}

type egressKey struct{}

type Observation struct {
	start     time.Time
	origin    Origin
	uid       *uint32
	uidSource string
	queue     *eventQueue
	lookupUID func() (uint32, bool)
}

var active atomic.Pointer[eventQueue]
var stream = struct {
	sync.Mutex
	seq       uint64
	listeners map[chan Event]struct{}
}{listeners: make(map[chan Event]struct{})}

func Enabled() bool { return active.Load() != nil }

func Subscribe() (<-chan Event, func()) {
	listener := make(chan Event, eventQueueCapacity)
	stream.Lock()
	stream.listeners[listener] = struct{}{}
	if active.Load() == nil {
		queue := newEventQueue()
		active.Store(queue)
		setEnhancedUIDObservation(true)
		go queue.run(publish)
	}
	stream.Unlock()
	return listener, func() {
		stream.Lock()
		delete(stream.listeners, listener)
		if len(stream.listeners) == 0 {
			if queue := active.Swap(nil); queue != nil {
				setEnhancedUIDObservation(false)
				close(queue.done)
			}
		}
		stream.Unlock()
	}
}

func WithUID(ctx context.Context, uid uint32) context.Context {
	return context.WithValue(ctx, uidKey{}, observedUID{uid, "socket"})
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
	if uid, ok := ctx.Value(uidKey{}).(observedUID); ok {
		if uid.uid != UnknownEnhancedUID {
			o.uid, o.uidSource = &uid.uid, uid.source
		}
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
	event := Event{
		Time: now.UnixMilli(), Delay: now.Sub(o.start).Milliseconds(),
		Qname: q.Name, Qtype: q.Qtype, Status: "failed", UID: o.uid, UIDSource: o.uidSource,
		AnswerSource: o.origin.Source, origin: o.origin, lookupUID: o.lookupUID,
		Route: o.origin.Route, OutboundTag: o.origin.OutboundTag,
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
