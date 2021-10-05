package main

import "testing"

func TestSum(t *testing.T) {
	msg := "Hello World"

	if msg != "Hello World" {
		t.Errorf("Hello from Hell")
	}
}
