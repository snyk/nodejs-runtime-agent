all: build-verbose
	docker run -it $(shell docker build -q .)

build-verbose:
	(cd .. && npm install)
	# docker not even once; unpacks the first level of directories
	mkdir -p agent/agent
	rsync -av --delete ../package.json ../methods.json ../lib agent/agent
	docker build .

.PHONY: build-verbose

