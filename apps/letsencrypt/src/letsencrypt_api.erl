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

-module(letsencrypt_api).
-author("Guillaume Bour <guillaume@bour.cc>").

-export([connect/1, close/1, get_nonce/2, new_reg/4, new_authz/5, challenge/6, new_cert/5, get_intermediate/1]).

-define(AGREEMENT_URL  , <<"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf">>).


connect({Domain, 443, _}) ->
    {ok, Conn} = shotgun:open(Domain, 443, https),
    Conn.


close(Conn) ->
    shotgun:close(Conn).


get_nonce(Conn, {_,_,BasePath}) ->
    {ok, #{headers := Headers}} = shotgun:head(Conn, BasePath++"/new-reg", #{}, #{}),
    proplists:get_value(<<"replay-nonce">>, Headers).


new_reg(Conn, Path, Key, Jws) ->
    Payload = #{
        resource  => 'new-reg',
        agreement => ?AGREEMENT_URL
    },

    Req = letsencrypt_jws:encode(Key, Jws, Payload),
    {ok, Nonce, _} = post(Conn, Path++"/new-reg", #{}, Req),

    Nonce.


new_authz(Conn, Path, Key, Jws, Domain) ->
    Payload = #{
        resource => 'new-authz',
        identifier => #{
            type => dns,
            value => Domain
        }
    },

    Req = letsencrypt_jws:encode(Key, Jws, Payload),
    %io:format("req= ~p~n", [Req]),
    {ok, Nonce, Body} = post(Conn, Path++"/new-authz", #{}, Req),

    % get http-01 challenge
    #{<<"challenges">> := Challenges} = jiffy:decode(Body, [return_maps]),
    [HttpChallenge] = lists:filter(fun(C) -> maps:get(<<"type">>, C, error) =:= <<"http-01">> end, Challenges),

    {HttpChallenge, Nonce}.


challenge(pre, _, _, Key, _, _HttpChallenge=#{<<"token">> := Token}) ->
    #{
        %path => "/.well-known/acme-challenge/",
        token      => Token,
        thumbprint => letsencrypt_jws:thumbprint(Key, Token)
    };


challenge(post, Conn, Path, Key, Jws, Thumbprint) ->
    Payload = #{
        resource => 'challenge',
        type => 'http-01',
        keyAuthorization => Thumbprint
    },

    Req = letsencrypt_jws:encode(Key, Jws, Payload),
    %io:format("req= ~p~n", [Req]),
    {ok, Nonce, _Body} = post(Conn, Path, #{}, Req),

    Nonce.


new_cert(Conn, Path, Key, Jws, Csr) ->
    Payload = #{
        resource => 'new-cert',
        csr      => Csr
    },

    Req = letsencrypt_jws:encode(Key, Jws, Payload),
    {ok, Nonce, Body} = post(Conn, Path++"/new-cert", #{}, Req),

    {Body, Nonce}.


post(Conn, Path, Headers, Content) ->
    %io:format("== POST ~p~n", [Path]),
    {ok, Resp} = shotgun:post(Conn, Path, Headers#{<<"Content-Type">> => <<"application/jose+json">>}, 
                              Content, #{}),
    %io:format("resp= ~p~n", [Resp]),
    #{body := Body, headers := RHeaders, status_code := _Status} = Resp,

    Nonce = proplists:get_value(<<"replay-nonce">>, RHeaders),
    {ok, Nonce, Body}.


get_intermediate({Domain, Port, Path}) ->
    {ok, Conn} = shotgun:open(Domain, Port, https),
    {ok, Resp} = shotgun:get(Conn, Path, #{}),

    %io:format("resp= ~p~n", [Resp]),
    #{body := Body} = Resp,
    {ok, Body}.

