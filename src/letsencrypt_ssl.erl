%% Copyright 2015-2020 Guillaume Bour
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

-export([private_key/2, cert_request/3, cert_autosigned/3, certificate/3]).

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
    io:format("CSR ~p~n", [CertFile]),

    {ok, RawCsr} = file:read_file(CertFile),
    [{'CertificationRequest', Csr, not_encrypted}] = public_key:pem_decode(RawCsr),

    io:format("csr= ~p~n", [Csr]),
    letsencrypt_utils:b64encode(Csr).


% create temporary (1 day) certificate with subjectAlternativeName
% used for tls-sni-01 challenge
-spec cert_autosigned(string(), string(), list(string())) -> {ok, string()}.
cert_autosigned(Domain, KeyFile, SANs) ->
    CertFile = "/tmp/"++Domain++"-tlssni-autosigned.pem",
    mkcert(request, Domain, CertFile, KeyFile, SANs).


-spec mkcert(request|autosigned, string(), string(), string(), list(string())) -> {ok, string()}.
mkcert(request, Domain, OutName, Keyfile, SANs) ->
    AltNames = lists:foldl(fun(San, Acc) ->
        <<Acc/binary, ", DNS:", San/binary>>
    end, <<"subjectAltName=DNS:", (bin(Domain))/binary>>, SANs),
    Cmd = io_lib:format("openssl req -new -key '~s' -out '~s' -subj '/CN=~s' -addext '~s'",
                        [Keyfile, OutName, Domain, AltNames]),

    _Status  = os:cmd(Cmd),
    io:format("mkcert(request):~p => ~p~n", [lists:flatten(Cmd), _Status]),
    {ok, OutName}.

% domain certificate only
certificate(Domain, DomainCert, CertsPath) ->
    FileName = CertsPath++"/"++Domain++".crt",
    %io:format("domain cert: ~p~nintermediate: ~p~n", [DomainCert, IntermediateCert]),
    %io:format("writing final certificate to ~p~n", [FileName]),

    file:write_file(FileName, DomainCert),
    FileName.

