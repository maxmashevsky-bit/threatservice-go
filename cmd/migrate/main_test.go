package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInvalidArgumentsFailBeforeDatabaseAccess(t *testing.T) {
	for _, args := range [][]string{nil, {"wrong"}, {"up", "status"}, {"-bad=SECRET_SENTINEL"}, {"-app-role"}, {"up", "-app-role=role"}, {"-app-role=role", "status"}, {"-app-role=role", "down"}} {
		var output bytes.Buffer
		err := run(args, func(string) string { t.Error("invalid arguments must not inspect database configuration"); return "" }, &output)
		if err == nil {
			t.Fatalf("accepted %v", args)
		}
		if strings.Contains(err.Error()+output.String(), "SECRET_SENTINEL") {
			t.Fatal("argument leaked")
		}
	}
}

func TestDestructiveGuardPrecedesDatabaseConnection(t *testing.T) {
	err := run([]string{"down"}, func(k string) string {
		if k == "DATABASE_URL" {
			t.Fatal("unguarded down attempted to use database configuration")
		}
		return ""
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "ALLOW_DESTRUCTIVE_MIGRATION=1") {
		t.Fatalf("got %v", err)
	}
}

func TestMigrationHelpAndMissingConfiguration(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"-h"}, func(string) string { t.Fatal("help requested configuration"); return "" }, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "up|down|status") {
		t.Fatal("help does not describe commands")
	}
	if err := run([]string{"up"}, func(string) string { return "" }, &bytes.Buffer{}); err == nil || err.Error() != "DATABASE_URL is required" {
		t.Fatalf("got %v", err)
	}
}
