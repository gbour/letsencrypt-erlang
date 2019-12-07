SHELL=bash

all:
	./rebar3 upgrade
	./rebar3 compile

dialize:
	if [[ "$$TRAVIS_OTP_RELEASE" > "18" ]] ; then\
		./rebar3 dialyzer;\
	fi

.PHONY: dialize
