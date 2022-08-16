.PHONY: test
test:
	curl -v -X POST http://localhost:8080/validate -H 'Content-Type: application/json' -d '{}'
