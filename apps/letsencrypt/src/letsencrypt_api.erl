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

-module(letsencrypt_api).
-author("Guillaume Bour <guillaume@bour.cc>").

-export([connect/1, close/1, get_nonce/2, new_reg/4, new_authz/6, challenge/6, challenge/3]).
-export([new_cert/5, get_intermediate/1]).

-import(letsencrypt_utils, [bin/1]).


-ifdef(TEST).
    -define(AGREEMENT_URL  , <<"http://boulder:4000/terms/v1">>).
    -define(debug(Fmt, Args), io:format(Fmt, Args)).
-else.
    -define(AGREEMENT_URL  , <<"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf">>).
    -define(debug(Fmt, Args), ok).
-endif.

-spec connect(letsencrypt:uri()) -> pid().
connect({Proto, Domain, Port, _}) ->
    {ok, Conn} = shotgun:open(Domain, Port, Proto),
    Conn.


-spec close(pid()) -> ok|{error,term()}.
close(Conn) ->
    shotgun:close(Conn).


-spec get_nonce(pid(), string()) -> binary().
get_nonce(Conn, BasePath) ->
    {ok, #{headers := Headers}} = shotgun:get(Conn, BasePath++"/new-reg", #{}, #{}),
    proplists:get_value(<<"replay-nonce">>, Headers).


-spec new_reg(pid(), string(), letsencrypt:ssl_privatekey(), letsencrypt:jws()) -> letsencrypt:nonce().
new_reg(Conn, Path, Key, Jws) ->
    Payload = #{
        resource  => 'new-reg',
        agreement => ?AGREEMENT_URL
    },

    Req = letsencrypt_jws:encode(Key, Jws, Payload),
    {ok, Nonce, _} = post(Conn, Path++"/new-reg", #{}, Req),

    Nonce.


-spec new_authz(pid(), string(), letsencrypt:ssl_privatekey(), letsencrypt:jws(), binary(),
                letsencrypt:challenge_type()) ->
    {'ok'   , map()               , letsencrypt:nonce()} |
    {'error', 'uncatched'|binary(), letsencrypt:nonce()}.
new_authz(Conn, Path, Key, Jws, Domain, ChallengeType) ->
    Payload = #{
        resource => 'new-authz',
        identifier => #{
            type => dns,
            value => Domain
        }
    },

    Req = letsencrypt_jws:encode(Key, Jws, Payload),
    %io:format("req= ~p~n", [Req]),
    {ok, Nonce, JsonBody} = post(Conn, Path++"/new-authz", #{}, Req),
    Body = jiffy:decode(JsonBody, [return_maps]),

    case Body of
        #{<<"status">> := <<"pending">>, <<"challenges">> := Challenges} ->
            % get http-01 challenge
            [Challenge] = lists:filter(fun(C) -> 
                    maps:get(<<"type">>, C, error) =:= bin(ChallengeType)
                end,
                Challenges
            ),

            {ok, Challenge, Nonce};

        #{<<"detail">> := Msg} ->
            {error, Msg, Nonce};

        _ ->
            {error, uncatched, Nonce}
    end.


-spec challenge(pre , pid(), string(), letsencrypt:ssl_privatekey(), letsencrypt:jws(), map()) -> map();
               (post, pid(), string(), letsencrypt:ssl_privatekey(), letsencrypt:jws(), binary()) -> letsencrypt:nonce().
challenge(pre, _, _, Key, _,
          _Challenge=#{<<"type">> := <<"http-01">>, <<"token">> := Token, <<"uri">> := Uri}) ->
    #{
        type       => 'http-01',
        %path => "/.well-known/acme-challenge/",
        uri        => Uri,
        token      => Token,
        thumbprint => letsencrypt_jws:thumbprint(Key, Token)
    };

challenge(pre, _, _, Key, _,
          _Challenge=#{<<"type">> := <<"tls-sni-01">>, <<"token">> := Token, <<"uri">> := Uri}) ->
    #{
        type       => 'tls-sni-01',
        %path => "/.well-known/acme-challenge/",
        uri        => Uri,
        token      => Token,
        thumbprint => letsencrypt_jws:thumbprint(Key, Token)
       % san        => letsencrypt_jws:san(Key, Token)
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


% 'ok'|'invalid' => make custom type (derived from atom())
-spec challenge(status, pid(), string()) -> {'ok'|'invalid', atom()|binary()}.
challenge(status, Conn, Path) ->
    {ok, Resp} = shotgun:get(Conn, Path, #{}),
    #{body := Body} = Resp,
    %io:format("challenge status: ~p~n", [Body]),

    Payload = #{<<"status">> := Status} = jiffy:decode(Body, [return_maps]),
    case status(Status) of
        invalid ->
            #{<<"detail">> := Err} = maps:get(<<"error">>, Payload, #{<<"detail">> => uncatched}),
            {invalid, Err};

        unknown ->
            {invalid, unknown_state};

        S       ->
            {S, undefined}
    end.


-spec new_cert(pid(), string(), letsencrypt:ssl_privatekey(), letsencrypt:jws(), letsencrypt:ssl_csr()) -> {binary(),letsencrypt:nonce()}.
new_cert(Conn, Path, Key, Jws, Csr) ->
    Payload = #{
        resource => 'new-cert',
        csr      => Csr
    },

    Req = letsencrypt_jws:encode(Key, Jws, Payload),
    {ok, Nonce, Body} = post(Conn, Path++"/new-cert", #{}, Req),

    {Body, Nonce}.


-spec post(pid(), string(), map(), binary()) -> {ok, letsencrypt:nonce(), binary()}.
post(Conn, Path, Headers, Content) ->
    ?debug("== POST ~p~n", [Path]),
    {ok, Resp} = shotgun:post(Conn, Path, Headers#{<<"Content-Type">> => <<"application/jose+json">>}, 
                              Content, #{}),
    ?debug("resp= ~p~n", [Resp]),
    #{body := Body, headers := RHeaders, status_code := _Status} = Resp,

    Nonce = proplists:get_value(<<"replay-nonce">>, RHeaders),
    {ok, Nonce, Body}.


-spec get_intermediate(letsencrypt:uri()) -> {ok, binary()}.
get_intermediate({Proto, Domain, Port, Path}) ->
    {ok, Conn} = shotgun:open(Domain, Port, Proto),
    {ok, Resp} = shotgun:get(Conn, Path, #{}),
    shotgun:close(Conn),

    %io:format("resp= ~p~n", [Resp]),
    #{body := Body} = Resp,
    {ok, Body}.

-spec status(binary()) -> atom().
status(<<"pending">>)    -> pending;
status(<<"processing">>) -> processing;
status(<<"valid">>)      -> valid;
status(<<"invalid">>)    -> invalid;
status(<<"revoked">>)    -> revoked;
status(_Status)       ->
    io:format("unknown status: ~p~n", [_Status]),
    unknown.

