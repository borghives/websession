.PHONY: all sync update tag

all: 
	@echo "Please specify a command: make init, make update, etc."

sync:
	git pull origin main; git pull

update:
	go get -u ; go mod tidy

tag:
	uptag-patch