#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp enable -sname factorial -mnesia debug verbose
main([IMode, Domain]) ->
	include_libs(),
	shotgun:start(),

	Mode = list_to_atom(IMode),
	io:format("Mode= ~p, Domain= ~p~n", [Mode, letsencrypt_utils:bin(Domain)]),
	%halt(1),

	CertPath = "/tmp/le/certs",
	WwwPath = "/tmp/le/webroot",
	letsencrypt:start([{mode, Mode}, staging, {cert_path, CertPath},
					   {port, 8099}]),
	letsencrypt:make_cert(letsencrypt_utils:bin(Domain), #{}),

	io:format("DONE"),
	ok.

include_libs() ->
    BaseDir = filename:dirname(escript:script_name()),
	io:format("~p~n", [BaseDir]),
    [ code:add_pathz(Path) || Path <- filelib:wildcard(BaseDir++"/_build/default/lib/*/ebin") ],
	ok.

