# CI Pipeline

This document describes the automated Continuous Integration (CI)
workflow used to validate the Go User Authentication API.

## Workflow Triggers

The GitHub Actions workflow runs on:

- Pushes to the `main` branch.
- Pull requests targeting the `main` branch.

Workflow configuration:

    .github/workflows/go.yml

## Execution Environment

The workflow runs on:

- Ubuntu 24.04.
- The Go version specified in `go.mod`.
- MySQL 8 as a database service.

GitHub Actions waits for the MySQL health check before running the
job steps.

The workflow configures database credentials and test-only JWT keys
through environment variables. Email and application file logging
are disabled during CI execution.

Database migrations are enabled for the test environment.

## Validation Steps

### 1. Go Formatting

The workflow runs `gofmt -l .` and fails if any Go source files
require formatting.

This keeps the codebase consistently formatted.

### 2. Static Analysis

The workflow runs:

    go vet ./...

`go vet` checks Go source code for suspicious constructs and
common programming mistakes.

### 3. Automated Tests with Race Detection

The workflow runs:

    go test -p 1 -race -count=1 ./...

Options:

- `-p 1`: Runs package test execution with one package at a time.
- `-race`: Enables the Go race detector.
- `-count=1`: Disables test result caching.

MySQL is available during this step because handler and repository
tests require a database connection.

### 4. Build Verification

The workflow runs:

    go build ./...

This verifies that all packages compile successfully.

## CI Pipeline Summary

A change is considered successfully validated when all workflow
steps complete without errors:

1. Repository checkout.
2. Go setup and dependency caching.
3. Go formatting verification.
4. Static analysis with `go vet`.
5. Automated tests with race detection.
6. Build verification.

## Local Verification

The following commands can be used to run the main checks locally
from the project root:

    gofmt -l .

    go vet ./...

    go test -p 1 -race -count=1 ./...

    go build ./...

**Database prerequisite:** Start the MySQL service and configure
the required environment variables before running database-dependent
tests locally.
