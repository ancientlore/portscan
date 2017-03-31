/*
portscan is a simple port scanner that tries to open a range of TCP connections to the given host.
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	host     = flag.String("host", "localhost", "Host or IP to scan")
	timeout  = flag.Duration("timeout", 1*time.Second, "Timeout per port")
	ports    = flag.String("range", "80,443", "Port ranges e.g. 80,443,200-1000,8000-9000")
	threads  = flag.Int("threads", 100, "Threads to use")
	showErrs = flag.Bool("verbose", false, "Show errors for failed ports")
)

func processRange(ctx context.Context, r string) chan int {
	c := make(chan int)
	done := ctx.Done()
	go func() {
		defer close(c)
		blocks := strings.Split(r, ",")
		for _, block := range blocks {
			rg := strings.Split(block, "-")
			if len(rg) != 1 && len(rg) != 2 {
				log.Print("Cannot interpret range: ", block)
				continue
			}
			var r1, r2 int
			var err error
			r1, err = strconv.Atoi(rg[0])
			if err != nil {
				log.Print("Cannot interpret range: ", block)
				continue
			}
			if len(rg) == 1 {
				r2 = r1
			} else {
				r2, err = strconv.Atoi(rg[1])
				if err != nil {
					log.Print("Cannot interpret range: ", block)
					continue
				}
			}
			for j := r1; j <= r2; j++ {
				select {
				case c <- j:
				case <-done:
					return
				}
			}
		}
	}()
	return c
}

func scanPorts(ctx context.Context, in <-chan int) chan string {
	out := make(chan string)
	done := ctx.Done()
	var wg sync.WaitGroup
	wg.Add(*threads)
	for i := 0; i < *threads; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case port, ok := <-in:
					if !ok {
						return
					}
					s := scanPort(port)
					select {
					case out <- s:
					case <-done:
						return
					}
				case <-done:
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func scanPort(port int) string {
	addr := fmt.Sprintf("%s:%d", *host, port)
	conn, err := net.DialTimeout("tcp", addr, *timeout)
	if err != nil {
		return fmt.Sprintf("%d: %s", port, err.Error())
	}
	conn.Close()
	return fmt.Sprintf("%d: OK", port)
}

func main() {
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("Scanning %s ports %s timeout %s threads %d\n", *host, *ports, (*timeout).String(), *threads)

	c := processRange(ctx, *ports)
	s := scanPorts(ctx, c)
	for x := range s {
		if *showErrs || strings.HasSuffix(x, ": OK") {
			fmt.Println(x)
		}
	}
}
