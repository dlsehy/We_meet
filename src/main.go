package main

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

func eventTypeToString(t uint8) string {
	switch t {
	case 0:
		return "exec"
	case 1:
		return "exit"
	case 2:
		return "open"
	case 3:
		return "tcp_connect"
	default:
		return "unknown"
	}
}

// 센서 로그 파싱용 구조체
type Event struct {
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	Comm      string `json:"comm"`
	EventType uint8  `json:"event_type"`
	Filename  string `json:"filename"`
	Saddr     string `json:"saddr"` 
	Daddr     string `json:"daddr"`  
	Dport     uint16 `json:"dport"`
}

// PID → Span 관리 매니저
type SpanManager struct {
	sync.Mutex
	spans map[uint32]trace.Span
	ctxs  map[uint32]context.Context
}

func NewSpanManager() *SpanManager {
	return &SpanManager{
		spans: make(map[uint32]trace.Span),
		ctxs:  make(map[uint32]context.Context),
	}
}

func (sm *SpanManager) StartSpan(e Event, tracer trace.Tracer) {
	sm.Lock()
	defer sm.Unlock()

	var ctx context.Context
	if parentCtx, ok := sm.ctxs[e.PPID]; ok {
		ctx = parentCtx
	} else {
		ctx = context.Background()
	}

	ctx, span := tracer.Start(ctx, e.Comm,
		trace.WithAttributes(
			attribute.Int("pid", int(e.PID)),
			attribute.Int("ppid", int(e.PPID)),
			attribute.String("event", eventTypeToString(e.EventType)),
		),
		trace.WithTimestamp(time.Now()),
	)
	sm.spans[e.PID] = span
	sm.ctxs[e.PID] = ctx
}

func (sm *SpanManager) EndSpan(e Event) {
	sm.Lock()
	defer sm.Unlock()

	if span, ok := sm.spans[e.PID]; ok {
		span.End(trace.WithTimestamp(time.Now()))
		delete(sm.spans, e.PID)
		delete(sm.ctxs, e.PID)
	}
}

// OpenTelemetry 초기화
func setupTracer() (trace.Tracer, func()) {
	exp, err := jaeger.New(
		jaeger.WithCollectorEndpoint(jaeger.WithEndpoint("http://localhost:14268/api/traces")),
	)
	if err != nil {
		log.Fatalf("failed to create Jaeger exporter: %v", err)
	}

	bsp := sdktrace.NewBatchSpanProcessor(exp)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			attribute.String(string(semconv.ServiceNameKey), "loader-agent"),
		)),
	)
	otel.SetTracerProvider(tp)

	return tp.Tracer("loader-agent"), func() {
		_ = tp.Shutdown(context.Background())
	}
}

func main() {
	tracer, shutdown := setupTracer()
	defer shutdown()

	cmd := exec.Command("./loader")
	stdout, err := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err != nil {
		log.Fatalf("failed to get stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start loader: %v", err)
	}

	scanner := bufio.NewScanner(stdout)
	sm := NewSpanManager()

	for scanner.Scan() {
		var e Event
		line := scanner.Text()

		// JSON 줄이 아니면 스킵 (예: "{"로 시작하지 않으면 무시)
		if !strings.HasPrefix(line, "{") {
			continue
		}

		if err := json.Unmarshal([]byte(line), &e); err != nil {
			log.Printf("invalid json: %s", line)
			log.Printf("error: %v", err)
			continue
		}

		// null 문자 제거
		e.Comm = strings.TrimRight(e.Comm, "\x00")
		e.Filename = strings.TrimRight(e.Filename, "\x00")

		switch eventTypeToString(e.EventType) {
		case "exec":
			sm.StartSpan(e, tracer)
		case "exit":
			sm.EndSpan(e)
		case "open", "tcp_connect":
			sm.Lock()
			sm.Unlock()
		
			// open, tcp_connect는 이미 존재하는 Span에 attribute 추가
			if span, ok := sm.spans[e.PID]; ok {
				span.AddEvent(eventTypeToString(e.EventType), trace.WithAttributes(
					attribute.String("filename", e.Filename),
					attribute.String("event", eventTypeToString(e.EventType)),
					attribute.Int("dport", int(e.Dport)),
				))
			}
		}
	}

	if err := cmd.Wait(); err != nil {
		log.Printf("loader exited with error: %v", err)
	}
}