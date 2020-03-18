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

% create key
-spec private_key(undefined|{new, file:filename_all()}|file:filename_all(), file:filename_all()) -> letsencrypt:ssl_privatekey().
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


-spec cert_request(letsencrypt:domain(), file:filename_all(), list(letsencrypt:domain())) -> letsencrypt:ssl_csr().
cert_request(Domain, CertsPath, SANs) ->
    KeyFile  = CertsPath ++ "/" ++ Domain ++ ".key",
    CertFile = CertsPath ++ "/" ++ Domain ++ ".csr",
    {ok, CertFile} = mkcert(request, Domain, CertFile, KeyFile, SANs),
    case file:read_file(CertFile) of
        {ok, RawCsr} ->
            [{'CertificationRequest', Csr, not_encrypted}] = public_key:pem_decode(RawCsr),
            letsencrypt_utils:b64encode(Csr);
        {error, enoent} ->
            io:format("cert_request: cert file ~p not found~n", [CertFile]),
            throw(file_not_found);
        {error, Err} ->
            io:format("cert_request: unknown error ~p~n", [Err]),
            throw(unknown_error)
    end.

% domain certificate only
certificate(Domain, DomainCert, CertsPath) ->
    FileName = CertsPath++"/"++Domain++".crt",
    file:write_file(FileName, DomainCert),
    FileName.

% create temporary (1 day) certificate with subjectAlternativeName
% used for tls-sni-01 challenge
-spec cert_autosigned(letsencrypt:domain(), file:filename_all(), list(letsencrypt:domain())) -> {ok, file:filename_all()}.
cert_autosigned(Domain, KeyFile, SANs) ->
    KeyDir = filename:dirname(KeyFile),
    CertFile = filename:join(KeyDir, <<(letsencrypt_utils:bin(Domain))/binary, "-tlssni-autosigned.pem">>),
    mkcert(autosigned, Domain, CertFile, KeyFile, SANs).


-spec mkcert(request|autosigned, letsencrypt:domain(), file:filename_all(), file:filename_all(), list(letsencrypt:domain())) -> {ok, file:filename_all()}.
mkcert(Type, Domain, OutName, Keyfile, SANs) ->
    Names = [ Domain | SANs ],
    NamesNr = lists:zip(Names, lists:seq(1,length(Names))),
    Cnf = [
        "[req]\n",
        "distinguished_name = req_distinguished_name\n",
        "x509_extensions = v3_req\n",
        "prompt = no\n",
        "[req_distinguished_name]\n",
        "CN = ", Domain, "\n",
        "[v3_req]\n",
        "subjectAltName = @alt_names\n",
        "[alt_names]\n"
    ] ++ [
        [ "DNS.", integer_to_list(Nr), " = ", Name, "\n" ] || {Name, Nr} <- NamesNr
    ],
    ConfDir = filename:dirname(OutName),
    ConfFile = filename:join(ConfDir, <<"letsencrypt_san_openssl.", (letsencrypt_utils:bin(Domain))/binary ,".cnf">>),
    ok = file:write_file(ConfFile, Cnf),
    Cmd = io_lib:format("openssl req -new -key '~s' -sha256 -out '~s' -subj '/CN=~s' -config '~s'", 
                        [Keyfile, OutName, Domain, ConfFile]),
    Cmd1 = case Type of
        request    -> [Cmd | " -reqexts v3_req" ];
        autosigned -> [Cmd | " -extensions v3_req -x509 -days 1" ]
    end,
    _Status = os:cmd(Cmd1),
    file:delete(ConfFile),
    {ok, OutName}.

