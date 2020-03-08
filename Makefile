DOCKER_IMAGE=egrets_builder
CFLAGS:=
ifdef DEBUG
CFLAGS=-DDEBUG
endif

all: egrets-main build-docker-image build-ebpf-object

build-docker-image:
	sudo docker build -t $(DOCKER_IMAGE) -f Dockerfile .

build-shell:
	sudo docker run -it --rm \
		-v $(PWD)/ebpf:/dist/ \
		--workdir=/dist/ \
		$(DOCKER_IMAGE) \
		bash -i

build-ebpf-object:
	sudo docker run --rm \
		-v $(PWD)/ebpf:/dist/ \
		--workdir=/dist/ \
		$(DOCKER_IMAGE) \
		make CFLAGS=$(CFLAGS)

egrets-main:
	go build
