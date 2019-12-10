#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp enable -sname factorial -mnesia debug verbose
main([Domain]) ->
	include_libs(),
	shotgun:start(),

	io:format("Domain= ~p~n", [letsencrypt_utils:bin(Domain)]),
	%halt(1),

	Key = letsencrypt_ssl:private_key(undefined, "/tmp/le/certs"),
    Jws = letsencrypt_jws:init(Key),

    %Uri = "https://acme-v02.api.letsencrypt.org/directory",
	Uri =  "https://acme-staging-v02.api.letsencrypt.org/directory",
    Opts = #{debug => true, netopts => #{timeout => 30000}},
	{ok, Directory} = letsencrypt_api:directory(Uri, Opts),
	io:format("directory = ~p~n", [Directory]),

	{ok, Nonce} = letsencrypt_api:nonce(Directory, Opts),
	io:format("~p~n", [Nonce]),

	%TODO: add contact email (optional) => reuse same account
	%	   requires to save key and use this to sign account query with
	%TODO: handle account status: "valid", "deactivated", and "revoked"
	%TODO: option to check account status only
	%TODO: option to list orders
	{ok, Location, Body, Nonce2} = letsencrypt_api:account(Directory, Key, Jws#{nonce => Nonce}, Opts),
	io:format("~p, ~p, ~p~n", [Location, Body, Nonce2]),

	Jws2 = #{
		alg => maps:get(alg, Jws),
		nonce => Nonce2,
		kid => Location
	},
	{ok, Location2, Body2, Nonce3} = letsencrypt_api:order(Directory, Key, Jws2,
														   letsencrypt_utils:bin(Domain),
														   Opts),
	io:format("~p, ~p, ~p~n", [Location2, Body2, Nonce3]),

	%TODO: iterate over list
	JBody = jiffy:decode(Body2, [return_maps]),
	AuthzUri = lists:nth(1, maps:get(<<"authorizations">>, JBody)),
	{ok, Location3, Body3, Nonce4} = letsencrypt_api:authorization(AuthzUri, Key,
																   Jws2#{nonce =>
																		 Nonce3},
																   Opts),
	io:format("~p, ~p, ~p~n", [Location3, Body3, Nonce4]),

	%extract http challenge (1st in list)
	%
	JBody2 = jiffy:decode(Body3, [return_maps]),
	Challenge = lists:nth(1, maps:get(<<"challenges">>, JBody2)),
	io:format("challenge= ~p~n", [Challenge]),

	% challenges types
	% - http-01
	%		token
	% - dsn-01
	% - tls-alpn-01
	% status:
	% - pending
	% - processing
	% - valid
	% - invalid
	JAcct = jiffy:decode(Body, [return_maps]),
	AcctKey = maps:get(<<"key">>, JAcct),
	Token = maps:get(<<"token">>, Challenge),
	Thumbprint = letsencrypt_jws:thumbprint2(AcctKey, Token),
	io:format("key: ~p, token: ~p, thumb: ~p~n", [AcctKey, Token, Thumbprint]),

	% write thumbprint to file
	{ok, Fd} = file:open(<<"/tmp/le/webroot/.well-known/acme-challenge/", Token/binary>>,
						[raw, write, binary]),
	file:write(Fd, Thumbprint),
	file:close(Fd),


	% wait enough time to let acme server to validate hash file
	timer:sleep(10000),

	%
	%Thumbprint := letsencrypt_jws:thumbprint2(AcctKey, 
	%letsencrypt_api:challenge2(Challenge, Key, Jws2#{nonce => Nonce4}, Opts),



	%io:format("biz ~p", [Key]),
	io:format("DONE"),
	ok.

include_libs() ->
    BaseDir = filename:dirname(escript:script_name()),
	io:format("~p~n", [BaseDir]),
    [ code:add_pathz(Path) || Path <- filelib:wildcard(BaseDir++"/_build/default/lib/*/ebin") ],
	ok.

