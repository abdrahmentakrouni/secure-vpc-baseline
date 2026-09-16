SHELL := /bin/bash
TF := terraform

.PHONY: init fmt fmt-check validate lint scan gate clean

init:
	$(TF) init -backend=false

fmt:
	$(TF) fmt -recursive

fmt-check:
	$(TF) fmt -check -recursive

validate: init
	$(TF) validate

lint:
	tflint --init
	tflint --recursive

scan:
	checkov -d . --framework terraform --compact
	tfsec .

# The same gate CI runs, one command for the desktop.
gate: fmt-check validate lint scan

clean:
	rm -rf .terraform .terraform.lock.hcl
