SHELL=bash

dialize:
	if [[ "$$TRAVIS_OTP_RELEASE" > "18" ]] ; then\
		./rebar3 dialyzer;\
	fi

.PHONY: dialize
