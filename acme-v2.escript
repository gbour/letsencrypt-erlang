#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp enable -sname factorial -mnesia debug verbose
main([Domain]) ->
	include_libs(),
	shotgun:start(),

	io:format("Domain= ~p~n", [letsencrypt_utils:bin(Domain)]),
	%halt(1),

	CertPath = "/tmp/le/certs",
	WwwPath = "/tmp/le/webroot",

	Key = letsencrypt_ssl:private_key(undefined, CertPath),
    Jws = letsencrypt_jws:init(Key),

    %Uri = "https://acme-v02.api.letsencrypt.org/directory",
	%Uri =  "https://acme-staging-v02.api.letsencrypt.org/directory",
    Opts = #{debug => true, netopts => #{timeout => 30000}},

	% 1. get directory
	{ok, Directory} = letsencrypt_api:directory(staging, Opts),
	io:format("directory = ~p~n", [Directory]),

	% 2. get first nonce
	{ok, Nonce} = letsencrypt_api:nonce(Directory, Opts),
	io:format("~p~n", [Nonce]),

	%TODO: add contact email (optional) => reuse same account
	%	   requires to save key and use this to sign account query with
	%TODO: handle account status: "valid", "deactivated", and "revoked"
	%TODO: option to check account status only
	%TODO: option to list orders
	{ok, Account, Location, Nonce2} = letsencrypt_api:account(Directory, Key, Jws#{nonce => Nonce}, Opts),
	io:format("~p, ~p, ~p~n", [Location, Account, Nonce2]),

	% build a new Jws with account uri
	Jws2 = #{
		alg   => maps:get(alg, Jws),
		nonce => Nonce2,
		kid   => Location
	},
	{ok, Order, OrderLocation, Nonce3} = letsencrypt_api:order(Directory,
		letsencrypt_utils:bin(Domain), Key, Jws2, Opts),
	io:format("~p, ~p, ~p~n", [OrderLocation, Order, Nonce3]),

	%TODO: iterate over list
	% Order may contains several authorizations urls
	AuthzUri = lists:nth(1, maps:get(<<"authorizations">>, Order)),
	{ok, Authorization, AuthzLocation, Nonce4} = 
		letsencrypt_api:authorization(AuthzUri, Key, Jws2#{nonce => Nonce3}, Opts),
	io:format("~p, ~p, ~p~n", [AuthzLocation, Authorization, Nonce4]),

	% extract http challenge (1st in list)
	% TODO: allow choosing challenge to validate
	Challenge = lists:nth(1, maps:get(<<"challenges">>, Authorization)),
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
	
	% compute thumbprint
	AcctKey    = maps:get(<<"key">>, Account),
	Token      = maps:get(<<"token">>, Challenge),
	Thumbprint = letsencrypt_jws:keyauth(AcctKey, Token),
	io:format("key: ~p, token: ~p, thumb: ~p~n", [AcctKey, Token, Thumbprint]),

	% write thumbprint to file
	io:format("writing thumbprint file~n"),
	{ok, Fd} = file:open(<<(letsencrypt_utils:bin(WwwPath))/binary, "/.well-known/acme-challenge/",
						   Token/binary>>, [raw, write, binary]),
	file:write(Fd, Thumbprint),
	file:close(Fd),


	% notify server - challenge is ready.
	{ok, _, _, Nonce5} = letsencrypt_api:challenge(Challenge, Key, Jws2#{nonce => Nonce4}, Opts),
	% wait enough time to let acme server to validate hash file
	io:format("wait 20secs~n"),
	timer:sleep(20000),

	% checking authorization (is challenge validated ?)
	% status should be 'valid'
	{ok, _, _, Nonce6} = letsencrypt_api:authorization(AuthzUri, Key,
		Jws2#{nonce => Nonce5}, Opts),

	% build & send CSR (with dedicated private key)
	Sans = [],
	#{file := KeyFile} = letsencrypt_ssl:private_key({new, Domain ++ ".key"}, CertPath),
	Csr = letsencrypt_ssl:cert_request(letsencrypt_utils:str(Domain), CertPath, Sans),
	io:format("key= ~p, csr= ~p~n", [KeyFile, Csr]),

	% we want 'finalize' value
	io:format("finalizing: sending csr~n"),
	{ok, FinOrder, _, Nonce7} = letsencrypt_api:finalize(Order, Csr, Key,
														 Jws2#{nonce => Nonce6}, Opts),

	% download certificate
	{ok, Cert} = letsencrypt_api:certificate(FinOrder, Key, Jws2#{nonce => Nonce7}, Opts),
	io:format("cert= ~p~n", [Cert]),
	{ok, Fd2} = file:open(CertPath++"/"++Domain++".crt", [raw, write, binary]),
	file:write(Fd2, Cert),
	file:close(Fd2),

	io:format("DONE"),
	ok.

include_libs() ->
    BaseDir = filename:dirname(escript:script_name()),
	io:format("~p~n", [BaseDir]),
    [ code:add_pathz(Path) || Path <- filelib:wildcard(BaseDir++"/_build/default/lib/*/ebin") ],
	ok.

