BIN=cmake-build-debug/hotp_verification
.PHONY: test test-power-cycle
test:
	# Test CLI calls for setup and usage
	$(BIN) id
	$(BIN) info
	$(BIN) set GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ 12345678
	$(BIN) check 755224
	$(BIN) check 287082
	$(BIN) check 359152
	# Fail if providing the same code succeeds (expected to fail)
	! $(BIN) check 359152
	# The error in the line above is expected.
	# Done. All good

test-power-cycle:
	# Test check after power-cycle
	$(BIN) check 403154 # 10th code
