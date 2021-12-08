.PHONY: venv

NAME    := aegis

venvdir := ./venv

all: test

define make_venv
	python3 -m venv --prompt $(NAME) $(1)
	( \
		source $(1)/bin/activate; \
		pip install -U "."; \
		deactivate; \
	)
endef

venv:
	$(call make_venv,$(venvdir))

clean:
	rm -rf $(venvdir)/
	rm -rf ./$(NAME)/__pycache__/

test:
	python3 -m unittest
