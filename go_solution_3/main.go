package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
    cnp := make(chan func(), 10)
    for i := 0; i < 4; i++ {
        go func() {
            for f := range cnp {
                f()
            }
        }()
    }
    cnp <- func() {
        fmt.Println("HERE1")
    }
    fmt.Println("Hello")
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, os.Interrupt, syscall.SIGTERM)
	fmt.Println("CTRL-C to shut down...")
	<-sigC
	fmt.Println("Shutting down...")
    close(cnp)
}
