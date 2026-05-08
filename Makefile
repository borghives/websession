DEPS=kosmos-go
DEPS_DIR=$(addprefix ../,$(DEPS))
DEPS_VERSION_TAG=$(addsuffix /tag,$(DEPS_DIR))

.PHONY: all sync update tag clean

all: 
	@echo "Please specify a command: make init, make update, etc."

sync:
	git pull origin main; git pull

update: $(DEPS_VERSION_TAG)
	@for version_file in $(DEPS_VERSION_TAG) ; do \
		go get -u $$(cat $$version_file) ; \
	done; \
	go get -u ; go mod tidy

tag:
	@uptag-patch
	@echo $$(getorigin)@$$(gettag) > tag

$(DEPS_VERSION_TAG) :
	@ $(MAKE) tag -C $(dir $@)

clean:
	rm -f tag