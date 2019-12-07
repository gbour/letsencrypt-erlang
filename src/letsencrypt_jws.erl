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

-module(letsencrypt_jws).
-author("Guillaume Bour <guillaume@bour.cc>").

-export([init/1, encode/3, thumbprint/2]).
% v2
-export([thumbprint2/2]).


-spec init(letsencrypt:ssl_privatekey()) -> letsencrypt:jws().
init(#{b64 := {N,E}}) ->
    #{
        alg => 'RS256',
        jwk =>  #{
            kty     => 'RSA',
            <<"n">> => N,
            <<"e">> => E
        },
        nonce => undefined
    }.


-spec encode(letsencrypt:ssl_privatekey(), letsencrypt:jws(), map()|empty) -> binary().
encode(#{raw := RSAKey}, Jws, Content) ->
    %io:format("~p~n~p~n", [Jws, Content]),
    Protected = letsencrypt_utils:b64encode(jiffy:encode(Jws)),
	Payload = case Content of
		% for POST-as-GET queries, payload is just an empty string
		empty -> <<"">>;
		_     -> letsencrypt_utils:b64encode(jiffy:encode(Content))
	end,

    Sign  = crypto:sign(rsa, sha256, <<Protected/binary, $., Payload/binary>>, RSAKey),
    Sign2 = letsencrypt_utils:b64encode(Sign),

    jiffy:encode({[
        %{header, {[]}},
        {protected, Protected},
        {payload  , Payload},
        {signature, Sign2}
    ]}).


-spec thumbprint(letsencrypt:ssl_privatekey(), binary()) -> binary().
thumbprint(#{b64 := {N,E}}, Token) ->
    % rfc7638 jwk thumbprint
    %NOTE: json payload requires to be encoded in keys alphabetical order
    Thumbprint = jiffy:encode({[
        {e, E},
        {kty, 'RSA'},
        {n, N}
    ]}, [force_utf8]),

    <<Token/binary, $., (letsencrypt_utils:b64encode(crypto:hash(sha256, Thumbprint)))/binary>>.

thumbprint2(#{<<"e">> := E, <<"n">> := N, <<"kty">> := Kty}, Token) ->
	Thumbprint = jiffy:encode({[
		{e, E},
		{kty, Kty},
		{n, N}
	]}, [force_utf8]),

    <<Token/binary, $., (letsencrypt_utils:b64encode(crypto:hash(sha256, Thumbprint)))/binary>>.
