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
 $erl> letsencrypt:certify(<<"mydomain.tld">>, []).
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


## Action modes

### webroot

### other modes
**TDB**
	

## Step by Step
