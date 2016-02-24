.PHONY: all


dev:
	eval "$(docker-machine env dev)"
	docker-compose build
	docker-compose up -d
	docker exec reversetwitter_web_1 python reverse_twitter/app.py --createdb --config=reverse_twitter/etc/config

default: dev
