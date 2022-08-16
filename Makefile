.PHONY: test
test:
	curl -v -X POST http://localhost:8080/validate/names -H 'Content-Type: application/json' -d '{}'
