# Run all tests with race detector
test:
    go test -v -race ./...

# Run tests and generate an HTML coverage report
test-coverage:
    go test -coverprofile=coverage.raw ./...
    grep -v -E '_templ\.go|mock_.*\.go|\.pb\.go' coverage.raw > coverage.out
    go tool cover -func=coverage.out | tail -1
    go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report: coverage.html"

# Run linter
lint:
    golangci-lint run

# Run linter with auto-fix
lint-fix:
    golangci-lint run --fix

# Format code with gofumpt (falls back to gofmt if gofumpt is not installed)
fmt:
    @which gofumpt > /dev/null 2>&1 && gofumpt -w . || gofmt -w .

# Tidy module dependencies
tidy:
    go mod tidy

# Remove build artifacts
clean:
    rm -rf coverage.raw coverage.out coverage.html

# Install pre-commit hook (TruffleHog secret scanning)
setup-hooks:
    cp scripts/pre-commit .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    @echo "Pre-commit hook installed"

# Pre-push check: lint and test
check: lint test
