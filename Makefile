.PHONY: all sync update

all: 
	@echo "Please specify a command: make init, make update, etc."

sync:
	git pull origin main

update:
	go get -u ; go mod tidy