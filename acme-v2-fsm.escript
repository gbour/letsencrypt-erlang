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
	                   {webroot_path, WwwPath}, {port, 8099}]),

	case Mode of
		slave ->
			io:format("MODE SLAVE~n", []),
			os:cmd("erlc -I _build/default/lib/ -o test test/test_slave_handler.erl"),
			code:add_pathz(filename:dirname(escript:script_name())++"/test"),
			elli:start_link([
				{name    , {local, my_test_slave_listener}},
				{callback, test_slave_handler},
				{port    , 5002}
			]);

		_ -> ok
	end,

	Ret = letsencrypt:make_cert(letsencrypt_utils:bin(Domain), #{async => false}),

	io:format("DONE: ~p~n", [Ret]),
	ok.

include_libs() ->
    BaseDir = filename:dirname(escript:script_name()),
	io:format("~p~n", [BaseDir]),
    [ code:add_pathz(Path) || Path <- filelib:wildcard(BaseDir++"/_build/default/lib/*/ebin") ],
	ok.

