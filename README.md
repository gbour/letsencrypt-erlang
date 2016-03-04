[![Build Status](https://travis-ci.org/gbour/letsencrypt-erlang.svg?branch=master)](https://travis-ci.org/gbour/letsencrypt-erlang)

# letsencrypt-erlang
Let's Encrypt client library for Erlang

## Overview


## Building

```
 $> ./rebar3 update
 $> ./rebar3 compile
```

## Quickstart

You must execute this example on the server targeted by _mydomain.tld_. 
Port 80 (http) must be opened and a webserver listening on it (line 1) and serving **/path/to/webroot/**
content.  
Both **/path/to/webroot** and **/path/to/certs** MUST be writtable by the erlang process

```erlang

 $> $(cd /path/to/webroot && python -m SimpleHTTPServer 80)&
 $> ./rebar3 shell
 $erl> application:ensure_all_started(letsencrypt).
 $erl> letsencrypt:start([{mode,webroot},{webroot_path,"/path/to/webroot"},{cert_path,"/path/to/certs"}]).
 $erl> letsencrypt:make_cert(<<"mydomain.tld">>, #{async => false}).
{ok, #{cert => <<"/path/to/certs/mydomain.tld.crt">>, key => <<"/path/to/certs/mydomain.tld.key">>}}
 $erl> ^C

 $> ls -1 /path/to/certs
 letsencrypt.key
 mydomain.tld.crt
 mydomain.tld.csr
 mydomain.tld.key
```

**Explanations**:

  During the certification process, letsencrypt server returns a challenge and then tries to query the challenge
  file from the domain name asked to be certified.
  So letsencrypt-erlang is writing challenge file under **/path/to/webroot** directory.
  Finally, keys and certificates are written in **/path/to/certs** directory.


## API
NOTE: if _optional_ is not written, parameter is required

* **letsencrypt:start(Params) :: starts letsencrypt client process**:
Params is a list of parameters, choose from the followings:
  * **staging** (optional): use staging API (generating fake certificates - default behavior is to use real API)
  * **{mode, Mode}**: choose running mode, where **Mode** is one of **webroot**, **slave**
  * **{cert_path, Path}**: pinpoint path to store generated certificates.
    Must be writable by erlang process
  
  Mode-specific parameters:
  * _webroot_ mode:
    * **{webroot_path, Path}**: pinpoint path to store challenge thumbprints.
      Must be writable by erlang process, and available through your webserver as root path

  returns:
    * **{ok, Pid}** with Pid the server process pid

* **letsencrypt:make_cert(Domain, Opts) :: generate a new certificate for the considered domain name**:
  * **Domain**: domain name (string or binary)
  * **Opts**: options map
    * **async** = true|false (optional, _true_ by default): 
    * **callback** (optional, used only when _async=true_): function called once certificate has been
      generated.

  returns:
    * in asynchronous mode, function returns **async**
    * in synchronous mode, or in asynchronous callback function:  
      * **{ok, #{cert => <<"/path/to/cert">>, key => <<"/path/to/key">>}}** on success  
      * **{error, Message}** on error

  examples:
    * sync mode (shell is locked several seconds waiting result)
  ```erlang
    > letsencrypt:make_cert(<<"mydomain.tld">>, #{async => false}).
    {ok, #{cert => <<"/path/to/cert">>, key => <<"/path/to/key">>}}

    > % domain tld is incorrect
    > letsencrypt:make_cert(<<"invalid.tld">>, #{async => false}).
    {error, <<"Error creating new authz :: Name does not end in a public suffix">>}

    > % domain web server does not return challenge file (ie 404 error)
    > letsencrypt:make_cert(<<"example.com">>, #{async => false}).
    {error, <<"Invalid response from http://example.com/.well-known/acme-challenge/Bt"...>>}

    > % returned challenge is wrong
    > letsencrypt:make_cert(<<"example.com">>, #{async => false}).
    {error,<<"Error parsing key authorization file: Invalid key authorization: 1 parts">>}
    or
    {error,<<"Error parsing key authorization file: Invalid key authorization: malformed token">>}
    or
    {error,<<"The key authorization file from the server did not match this challenge"...>>>}
  ```
    * async mode ('async' is written immediately)
  ```erlang
    > F = fun({Status, Result}) -> io:format("completed: ~p (result= ~p)~n") end.
    > letsencrypt:make_cert(<<"example.com">>, #{async => true, callback => F}).
    async
    >
    ...
    completed: ok (result= #{cert => <<"/path/to/cert">>, key => <<"/path/to/key">>})
  ```




## Action modes

### webroot

### slave

Use this mode if you already have a cowboy server running on port 80 in your application

```erlang

on_complete({State, Data}) ->
    io:format("letsencrypt completed: ~p (data: ~p)~n", [State, Data]).

main() ->
    Dispatch = cowboy_router:compile([
        {'_', [
            {<<"/.well-known/acme-challenge/:token">>, letsencrypt_cowboy_handler, []}
        ]}
    ]),
    {ok, _} = cowboy:start_http(my_http_listener, 1, [{port, 80}],
        [{env, [{dispatch, Dispatch}]}]
    ),

    letsencrypt:start([{mode,slave}, staging, {cert_path,"/path/to/certs"}]),
    letsencrypt:make_cert(<<"mydomain.tld">>, #{callback => fun on_complete/1}),

    ok.
```

### other modes
**TDB**
	

## Step by Step
