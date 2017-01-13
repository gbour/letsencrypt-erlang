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

-export([connect/1, connect/2, close/1, get_nonce/2, new_reg/4, new_authz/6, challenge/6, challenge/3]).
-export([new_cert/5, get_intermediate/2]).

-import(letsencrypt_utils, [bin/1]).

% RFC7807 Problem Report type
-record(problem, {type=none,instance=none,info=[]}).

-ifdef(TEST).
    -define(AGREEMENT_URL  , <<"http://boulder:4000/terms/v1">>).
    -define(debug(Fmt, Args), io:format(Fmt, Args)).
-else.
    -define(AGREEMENT_URL  , <<"https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf">>).
    -define(debug(Fmt, Args), ok).
-endif.

-spec connect(letsencrypt:uri()) -> pid().
connect(Uri) ->
    connect(Uri, #{}).
-spec connect(letsencrypt:uri(), Opts::map()) -> pid().
connect({Proto, Domain, Port, _}, Opts) ->
    {ok, Conn} = shotgun:open(Domain, Port, Proto, Opts),
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
            Err = maps:get(<<"error">>, Payload, #{<<"detail">> => uncatched}),
            {invalid, problem_report(Err)};

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


-spec post(pid(), string(), map(), binary()) -> {ok, letsencrypt:nonce(), binary()}|{error,term()}|#problem{}.
post(Conn, Path, Headers, Content) ->
    ?debug("== POST ~p~n", [Path]),
    {ok, Resp} = shotgun:post(Conn, Path, Headers#{<<"Content-Type">> => <<"application/jose+json">>}, 
                              Content, #{}),
    ?debug("resp= ~p~n", [Resp]),
    #{body := Body, headers := RHeaders, status_code := Status} = Resp,

    RespContentType = case proplists:get_value(<<"content-type">>, RHeaders) of
			  undefined -> undefined;
			  T -> cow_http_hd:parse_content_type(T)
		      end,

    case {Status, RespContentType} of
	{_, {<<"application">>, <<"problem+json">>, _}} ->
	    problem_report(Status, Body);
	{X, _} when X >= 400 ->
	    {error, {http, X}};
	_ ->
	    Nonce = proplists:get_value(<<"replay-nonce">>, RHeaders),
	    {ok, Nonce, Body}
    end.

-spec get_intermediate(letsencrypt:uri(), Opts::map()) -> {ok, binary()}.
get_intermediate({Proto, Domain, Port, Path}, Opts) ->
    {ok, Conn} = shotgun:open(Domain, Port, Proto, Opts),
    {ok, Resp} = shotgun:get(Conn, Path, #{}),
    shotgun:close(Conn),

    %io:format("resp= ~p~n", [Resp]),
    #{body := Body, status_code := 200} = Resp,
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

-spec problem_report(integer(), binary()) -> #problem{}.
problem_report(Status, JsonBin) ->
    {Kvs} = jiffy:decode(JsonBin),
    lists:foldl(fun({K,V},P) -> assort_problem(K,V,P) end,
		#problem{info=[{status,Status}]}, Kvs).
-spec problem_report(map()) -> #problem{}.
problem_report(JsonMap) ->
    maps:fold(fun assort_problem/3, #problem{}, JsonMap).

-spec assort_problem(binary(),term(),#problem{}) -> #problem{}.
assort_problem(<<"type">>, T, Prob)     -> Prob#problem{type=problem_type(T)};
assort_problem(<<"instance">>, T, Prob) -> Prob#problem{instance=T};
assort_problem(K, V, Prob) ->
    InfoKey = case K of
		  <<"title">> -> title;
		  <<"detail">> -> detail;
		  <<"status">> -> status;
		  Other -> Other
	      end,
    Prob#problem{info=[{InfoKey,V}|Prob#problem.info]}.

-spec problem_type(binary()) -> binary() | {atom(),atom()}.
problem_type(<<"urn:ietf:params:acme:error:", X/binary>>) ->
    {acme,
     case X of
	 <<"badCSR">> -> badCSR;
	 <<"badNonce">> -> badNonce;
	 <<"badSignatureAlgorithm">> -> badSignatureAlgorithm;
	 <<"caa">> -> caa;
	 <<"connection">> -> connection;
	 <<"dnssec">> -> dnssec;
	 <<"invalidContact">> -> invalidContact;
	 <<"malformed">> -> malformed;
	 <<"rateLimited">> -> rateLimited;
	 <<"rejectedIdentifier">> -> rejectedIdentifier;
	 <<"serverInternal">> -> serverInternal;
	 <<"tls">> -> tls;
	 <<"unauthorized">> -> unauthorized;
	 <<"unknownHost">> -> unknownHost;
	 <<"unsupportedIdentifier">> -> unsupportedIdentifier;
	 <<"userActionRequired">> -> userActionRequired;
	 _ -> X
     end
    };
problem_type(<<"urn:acme:error:", X/binary>>) -> problem_type(<<"urn:ietf:params:acme:error:", X/binary>>);
problem_type(X) -> X.
