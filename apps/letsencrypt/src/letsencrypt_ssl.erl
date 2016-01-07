%% Copyright 2015 Guillaume Bour
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

-export([private_key/2, cert_request/2, certificate/4]).

-include_lib("public_key/include/public_key.hrl").

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


-spec cert_request(string(), string()) -> letsencrypt:ssl_csr().
cert_request(Domain, CertsPath) ->
    Cmd =  "openssl req -new -key '"++CertsPath++"/"++Domain++".key' -subj '/CN="++Domain++"' -out '"++CertsPath++"/"++Domain++".csr'",
    _R = os:cmd(Cmd),
    %io:format("~p: ~p~n", [Cmd, R]),

    {ok, RawCsr} = file:read_file(CertsPath++"/"++Domain++".csr"),
    [{'CertificationRequest', Csr, not_encrypted}] = public_key:pem_decode(RawCsr),

    %io:format("csr= ~p~n", [Csr]),
    letsencrypt_utils:b64encode(Csr).


-spec certificate(string(), binary(), binary(), string()) -> string().
certificate(Domain, DomainCert, IntermediateCert, CertsPath) ->
    FileName = CertsPath++"/"++Domain++".crt",
    %io:format("domain cert: ~p~nintermediate: ~p~n", [DomainCert, IntermediateCert]),

    file:write_file(FileName, <<"-----BEGIN CERTIFICATE-----\n",
                                (base64:encode(DomainCert))/binary, $\n,
                                "-----END CERTIFICATE-----\n",
                                IntermediateCert/binary>>
    ),

    FileName.

