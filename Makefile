BINARY := boxguard


.PHONY: build clean test run

# Build the project
build:
	go build -o boxguard .

# Clean build artifacts
clean:
	rm -f boxguard

# Run tests
test:
	go test ./...

# Run the scanner
run: build
	./boxguard scan --vagrant-path .

# Install dependencies
deps:
	go mod tidy

# Build for different platforms
build-linux:
	GOOS=linux GOARCH=amd64 go build -o boxguard-linux .

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -o boxguard-darwin .

build-windows:
	GOOS=windows GOARCH=amd64 go build -o boxguard.exe .

# Build all platforms
build-all: build-linux build-darwin build-windows

# Help
help:
	@echo "Available targets:"
	@echo "  build       - Build the project"
	@echo "  clean       - Clean build artifacts"
	@echo "  test        - Run tests"
	@echo "  run         - Build and run scanner"
	@echo "  deps        - Install dependencies"
	@echo "  build-linux - Build for Linux"
	@echo "  build-darwin - Build for macOS"
	@echo "  build-windows - Build for Windows"
	@echo "  build-all   - Build for all platforms"
	@echo "  help        - Show this help"