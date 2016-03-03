.PHONY: all build

MACHINE?=dev
FLAG?=0

export MACHINE

ifeq ($(FLAG), 0)
build:
	$(info "Setting environment $(MACHINE)")
	./docker_env.sh
else
build:
	$(info "Building $(MACHINE)")
	docker-compose build --force-rm
	docker-compose up -d
	docker exec reversetwitter_web_1 python reverse_twitter/app.py --createdb --config=reverse_twitter/etc/config
endif

default: build
