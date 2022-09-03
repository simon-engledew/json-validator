.PHONY: test
test:
	curl -v -X POST http://localhost:8080/schemas/names.json -H 'Content-Type: application/json' -d '{}'
