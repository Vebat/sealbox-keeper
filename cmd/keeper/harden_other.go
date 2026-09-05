//go:build !linux

package main

import "errors"

// harden has nothing to do outside Linux; the warning tells the operator
// that core dumps and ptrace are not restricted here.
func harden() error {
	return errors.New("process hardening (no core dumps, non-dumpable) is only implemented on Linux")
}
