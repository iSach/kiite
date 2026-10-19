.PHONY: build install test clean

build:
	./scripts/build.sh

install: build
	./scripts/install.sh

test:
	./scripts/test.sh

clean:
	rm -rf build
