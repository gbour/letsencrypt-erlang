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


## API
NOTE: if _optional_ is not written, parameter is required

* **letsencrypt:start(Params) :: starts letsencrypt client process**:
Params is a list of parameters, choose from the followings:
  * **staging** (optional): use staging API (generating fake certificates - default behavior is to use real API)
  * **{mode, Mode}**: choose running mode, where **Mode** is **webroot** (only one available at now)
  
  Each mode has a specific list of parameters:
  * _webroot_ mode:
    * **{webroot_path, Path}**: pinpoint path to store challenge thumbprints.
      Must be writable by erlang process, and available through your webserver as root path
    * **{cert_path, Path}**: pinpoint path to store generated certificates.
      Must be writable by erlang process


* **letsencrypt:certify(Domain, Opts) :: generate a new certificate for the considered domain name**:
  * **Domain**: domain name (string or binary)
  * **Opts**: options list (empty for now)



## Action modes

### webroot

### other modes
**TDB**
	

## Step by Step
