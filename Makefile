SHELL=bash

all:
	./rebar3 upgrade
	./rebar3 compile

dialize:
	./rebar3 dialyzer;\

.PHONY: dialize
