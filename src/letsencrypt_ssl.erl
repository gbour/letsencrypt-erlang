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

-export([private_key/2, cert_request/3, cert_autosigned/3, certificate/4]).

-include_lib("public_key/include/public_key.hrl").
-import(letsencrypt_utils, [bin/1]).

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
    KeyFile  = CertsPath ++ "/" ++ Domain ++ ".key",
    CertFile = CertsPath ++ "/" ++ Domain ++ ".csr",
    {ok, CertFile} = mkcert(request, Domain, CertFile, KeyFile, SANs),
    %io:format("CSR ~p~n", [CertFile]),

    {ok, RawCsr} = file:read_file(CertFile),
    [{'CertificationRequest', Csr, not_encrypted}] = public_key:pem_decode(RawCsr),

    %io:format("csr= ~p~n", [Csr]),
    letsencrypt_utils:b64encode(Csr).


% create temporary (1 day) certificate with subjectAlternativeName
% used for tls-sni-01 challenge
-spec cert_autosigned(string(), string(), list(string())) -> {ok, string()}.
cert_autosigned(Domain, KeyFile, SANs) ->
    CertFile = "/tmp/"++Domain++"-tlssni-autosigned.pem",
    mkcert(autosigned, Domain, CertFile, KeyFile, SANs).


-spec mkcert(request|autosigned, string(), string(), string(), list(string())) -> {ok, string()}.
mkcert(request, Domain, OutName, Keyfile, []) ->
%    CertFile = CertsPath++"/"++Domain++".csr",
    Cmd = io_lib:format("openssl req -new -key '~s' -subj '/CN=~s' -out '~s'", [Keyfile, Domain, OutName]),
    _R  = os:cmd(Cmd),
    %io:format("mkcert(request):~p => ~p~n", [lists:flatten(Cmd), _R]),

    {ok, OutName};
mkcert(Type, Domain, OutName, Keyfile, SANs) ->
    %io:format("USE SANS~n"),
    <<$,, SANEntry/binary>> = lists:foldl(fun(X, Acc) -> <<Acc/binary, ",DNS:", X/binary>> end, <<>>, SANs),

    {ok, File} = file:read_file("/etc/ssl/openssl.cnf"),
    File2 = <<File/binary, "\n[SAN]\nsubjectAltName=DNS:", (bin(Domain))/binary,$,, SANEntry/binary>>,
    ConfFile = <<"/tmp/letsencrypt_san_openssl.cnf">>,
    file:write_file(ConfFile, File2),

    Cmd = io_lib:format(
        "openssl req -new -key '~s' -out '~s' -subj '/CN=~s' -config '~s'", 
        [Keyfile, OutName, Domain, ConfFile]),
    Cmd1 = case Type of
        request    -> [Cmd | " -reqexts SAN" ];
        autosigned -> [Cmd | " -extensions SAN -x509 -sha256 -days 1" ]
    end,

    _Status  = os:cmd(Cmd1),
    %io:format("mkcert(~p): ~p => ~p~n", [Type, lists:flatten(Cmd1), _Status]),

    file:delete(ConfFile),
    {ok, OutName}.


-spec certificate(string(), binary(), binary(), string()) -> string().
certificate(Domain, DomainCert, IntermediateCert, CertsPath) ->
    FileName = CertsPath++"/"++Domain++".crt",
    %io:format("domain cert: ~p~nintermediate: ~p~n", [DomainCert, IntermediateCert]),
    %io:format("writing final certificate to ~p~n", [FileName]),

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
