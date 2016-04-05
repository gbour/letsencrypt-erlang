%% Copyright 2015-2016 Guillaume Bour
%% 
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%% http://www.apache.org/licenses/LICENSE-2.0
%% 
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(letsencrypt_ssl).
-author("Guillaume Bour <guillaume@bour.cc>").

-export([private_key/2, cert_request/3, certificate/4]).

-include_lib("public_key/include/public_key.hrl").

-import(letsencrypt_utils, [bin/1, str/1]).

% create key
-spec private_key(undefined|{new, string()}|string(), string()) -> letsencrypt:ssl_privatekey().
private_key(undefined, CertsPath) ->
    private_key({new, "letsencrypt.key"}, CertsPath);

private_key({new, KeyFile}, CertsPath) ->
    FileName = CertsPath++"/"++KeyFile,
    Cmd = "openssl genrsa -out '"++FileName++"' 2048",
    _R = os:cmd(Cmd),

    private_key(FileName, CertsPath);

private_key(KeyFile, _) ->
    {ok, Pem} = file:read_file(KeyFile),
    [Key]     = public_key:pem_decode(Pem),
    #'RSAPrivateKey'{modulus=N, publicExponent=E, privateExponent=D} = public_key:pem_entry_decode(Key),

    #{
        raw => [E,N,D],
        b64 => {
            letsencrypt_utils:b64encode(binary:encode_unsigned(N)),
            letsencrypt_utils:b64encode(binary:encode_unsigned(E))
        },
        file => KeyFile
    }.


-spec cert_request(string(), string(), list(string())) -> letsencrypt:ssl_csr().
cert_request(Domain, CertsPath, SANs) ->
    {ok, CertFile} = cert_request2(Domain, CertsPath, SANs),
    %io:format("CSR ~p~n", [CertFile]),

    {ok, RawCsr} = file:read_file(CertFile),
    [{'CertificationRequest', Csr, not_encrypted}] = public_key:pem_decode(RawCsr),

    %io:format("csr= ~p~n", [Csr]),
    letsencrypt_utils:b64encode(Csr).


-spec cert_request2(string(), string(), list(string())) -> {ok, string()}.
cert_request2(Domain, CertsPath, []) ->
    CertFile = CertsPath++"/"++Domain++".csr",
    Cmd =  "openssl req -new -key '"++CertsPath++"/"++Domain++".key' -subj '/CN="++Domain++"' -out '"++CertFile++"'",
    _R = os:cmd(Cmd),
    %io:format("~p: ~p~n", [Cmd, _R]),
    %
    {ok, CertFile};
cert_request2(Domain, CertsPath, SANs) ->
    %io:format("USE SANS~n"),
    <<$,, SANEntry/binary>> = lists:foldl(fun(X, Acc) -> <<Acc/binary, ",DNS:", X/binary>> end, <<>>, SANs),

    {ok, File} = file:read_file("/etc/ssl/openssl.cnf"),
    File2 = <<File/binary, "\n[SAN]\nsubjectAltName=DNS:", (bin(Domain))/binary,$,, SANEntry/binary>>,
    ConfFile = <<"/tmp/letsencrypt_san_openssl.cnf">>,
    file:write_file(ConfFile, File2),

    CertFile = CertsPath++"/"++Domain++".csr",
    _Status  = os:cmd(str(<<"openssl req -new -key '", (bin(CertsPath))/binary, $/, (bin(Domain))/binary,
        ".key' -out '", (bin(CertFile))/binary, "' -subj '/CN=", (bin(Domain))/binary,
        "' -reqexts SAN -config ", ConfFile/binary>>)),
    %io:format("ret= ~p~n", [_Status]),

    file:delete(ConfFile),
    {ok, CertFile}.

-spec certificate(string(), binary(), binary(), string()) -> string().
certificate(Domain, DomainCert, IntermediateCert, CertsPath) ->
    FileName = CertsPath++"/"++Domain++".crt",
    %io:format("domain cert: ~p~nintermediate: ~p~n", [DomainCert, IntermediateCert]),

    file:write_file(FileName, <<(pem_format(DomainCert))/binary, $\n, IntermediateCert/binary>>),
    FileName.


-spec pem_format(binary()) -> binary().
pem_format(Cert) ->
    <<"-----BEGIN CERTIFICATE-----\n",
      (pem_format(base64:encode(Cert), <<>>))/binary, $\n,
      "-----END CERTIFICATE-----">>.

-spec pem_format(binary(), binary()) -> binary().
pem_format(<<>>, <<$\n, Fmt/binary>>) ->
    Fmt;
pem_format(<<Head:64/binary, Rest/binary>>, Fmt)  ->
    pem_format(Rest, <<Fmt/binary, $\n, Head/binary>>);
pem_format(Rest, Fmt)  ->
    pem_format(<<>>, <<Fmt/binary, $\n, Rest/binary>>).
