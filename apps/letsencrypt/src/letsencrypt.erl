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

-module(letsencrypt).
-author("Guillaume Bour <guillaume@bour.cc>").
-behaviour(gen_fsm).

-export([make_cert/2, make_cert_bg/2, get_challenge/0]).
-export([start/1, stop/0, init/1, handle_event/3, handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).
-export([idle/3, pending/3, valid/3]).

-import(letsencrypt_utils, [bin/1, str/1]).

% uri format compatible with shotgun library
-type mode()           :: 'webroot'|'slave'|'standalone'.
-type uri()            :: {Proto::(http|https), Host::string(), Port::integer(), Path::string()}.
-type nonce()          :: binary().
-type jws()            :: #{'alg' => 'RS256', 'jwk' => map(), nonce => undefined|letsencrypt:nonce() }.
-type ssl_privatekey() :: #{'raw' => crypto:rsa_private(), 'b64' => {binary(), binary()}, 'file' => string()}.
-type ssl_csr()        :: binary().


-ifdef(TEST).
    -define(STAGING_API_URL      , "http://127.0.0.1:4000/acme").
    -define(DEFAULT_API_URL      , "").
    -define(INTERMEDIATE_CERT_URL, "http://127.0.0.1:3099/test/test-ca.pem").
-else.
    -define(STAGING_API_URL      , "https://acme-staging.api.letsencrypt.org/acme").
    -define(DEFAULT_API_URL      , "https://acme-v01.api.letsencrypt.org/acme").
    %TODO: dynamically get xs certificate given the one used to sign the generated one
    -define(INTERMEDIATE_CERT_URL, "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem").
-endif.
%-define(AGREEMENT_URL  , <<"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf">>).

-define(WEBROOT_CHALLENGE_PATH, <<"/.well-known/acme-challenge">>).

-record(state, {
    acme_srv = ?DEFAULT_API_URL     :: uri() | string(),
    key_file  = undefined           :: undefined | string(),
    cert_path = "/tmp"              :: string(),

    mode = undefined                :: undefined | mode(),
    % mode = webroot
    webroot_path = undefined        :: undefined | string(),
    % mode = standalone
    port = 80                       :: integer(),

    intermediate_cert = undefined   :: undefined | binary(),

    % state datas
    conn  = undefined               :: undefined | pid(),
    nonce = undefined               :: undefined | nonce(),
    domain = undefined              :: undefined | binary(),
    sans  = []                      :: list(string()),
    key   = undefined               :: undefined | ssl_privatekey(),
    jws   = undefined               :: undefined | jws(),

    challenge = undefined           :: undefined | map()
}).

-type state() :: #state{}.

-spec start(list()) -> {'ok', pid}|{'error', {'already_started',pid()}}.
start(Args) ->
    gen_fsm:start_link({global, ?MODULE}, ?MODULE, Args, []).

-spec stop() -> 'ok'.
stop() ->
    %NOTE: maintain compatibility with 17.X versions
    %gen_fsm:stop({global, ?MODULE})
    gen_fsm:sync_send_all_state_event({global, ?MODULE}, stop).


%%
%% Args:
%%   staging
-spec init(list( atom() | {atom(),any()} )) -> {ok, idle, state()}.
init(Args) ->
    {Args2, State} = mode_opts(proplists:get_value(mode, Args), Args),
    State2 = getopts(Args2, State),
    %io:format("state= ~p~n", [State2]),

    {ok, {Proto, _, Host, Port, Path, _}} = http_uri:parse(State2#state.acme_srv),
    AcmeSrv = {Proto, Host, Port, Path},

    % loading private key into memory
    Key = letsencrypt_ssl:private_key(State2#state.key_file, State2#state.cert_path),
    Jws = letsencrypt_jws:init(Key),

    {ok, {IProto, _, IHost, IPort, IPath, _}} = http_uri:parse(?INTERMEDIATE_CERT_URL),
    {ok, IntermediateCert} = letsencrypt_api:get_intermediate({IProto, IHost, IPort, IPath}),

    {ok, idle, State2#state{acme_srv=AcmeSrv, key=Key, jws=Jws, intermediate_cert=IntermediateCert}}.

-spec mode_opts(mode(), list(atom()|{atom(),any()})) -> {list(atom()|{atom(),any()}), state()}.
mode_opts(Mode, Args) ->
    mode_opts(Mode, proplists:delete(mode, Args), #state{mode=Mode}).

-spec mode_opts(mode(), list(atom()|{atom(),any()}), state()) -> {list(atom()|{atom(),any()}), state()}.
mode_opts(webroot, [{webroot_path, Path}|Args], State) ->
    %TODO: check directory is writeable
    os:cmd(string:join(["mkdir -p '", Path, str(?WEBROOT_CHALLENGE_PATH), "'"], "")),

    mode_opts(webroot, Args, State#state{webroot_path=Path});
mode_opts(standalone, [{port, Port}|Args], State) ->
    mode_opts(standalone, Args, State#state{port=Port});

% general opts, we ignore it for now
mode_opts(M, [H|Args], State) ->
    {Args2, State2} = mode_opts(M, Args, State),
    {[H|Args2], State2};
mode_opts(_, [], State) ->
    {[], State}.
    

-spec getopts(list(atom()|{atom(),any()}), state()) -> state().
getopts([], State) ->
    State;
getopts([staging|Args], State) ->
    getopts(
        Args,
        State#state{acme_srv = ?STAGING_API_URL}
    );
getopts([{key_file, KeyFile}|Args], State) ->
    getopts(
        Args,
        State#state{key_file = KeyFile}
    );
getopts([{cert_path, Path}|Args], State) ->
    getopts(
        Args,
        State#state{cert_path = Path}
    );
getopts([Unk|_], _) ->
    io:format("unknow parameter: ~p~n", [Unk]),
    %throw({badarg, io_lib:format("unknown ~p parameter", [Unk])}).
    throw(badarg).
    
%%
%%
%%

-spec make_cert(string()|binary(), map()) -> {'ok', #{cert => binary(), key => binary()}}|
                                             {'error','invalid'}|
                                             async.
make_cert(Domain, Opts=#{async := false}) ->
    make_cert_bg(Domain, Opts);
% default to async = true
make_cert(Domain, Opts) ->
    Pid = erlang:spawn(?MODULE, make_cert_bg, [Domain, Opts#{async => true}]),
    async.

-spec make_cert_bg(string()|binary(), map()) -> {'ok', map()}|{'error', 'invalid'}.
make_cert_bg(Domain, Opts=#{async := Async}) ->
    Ret = case gen_fsm:sync_send_event({global, ?MODULE}, {create, bin(Domain), Opts}, 15000) of
        {error, Err} ->
            %io:format("error: ~p~n", [Err]),
            {error, Err};

        ok ->
            %io:format("ok: ~p~n", [Path]),

            case wait_valid(10) of
                ok ->
                    gen_fsm:sync_send_event({global, ?MODULE}, finalize, 15000);

                Error ->
                    gen_fsm:send_all_state_event({global, ?MODULE}, reset),
                    Error
            end
    end,

    case Async of
        true ->
            Callback = maps:get(callback, Opts, fun(_) -> ok end),
            Callback(Ret);

        _    ->
            ok
    end,

    Ret.

-spec wait_valid(0..10) -> ok|{error, any()}.
wait_valid(X) ->
    wait_valid(X,X).

-spec wait_valid(0..10, 0..10) -> ok|{error, any()}.
wait_valid(0,_) ->
    {error, timeout};
wait_valid(Cnt,Max) ->
    case gen_fsm:sync_send_event({global, ?MODULE}, check, 15000) of
        {valid  , _}   -> ok;
        {pending, _}   ->
            timer:sleep(500*(Max-Cnt+1)),
            wait_valid(Cnt-1,Max);
        {_      , Err} -> {error, Err}
    end.

-spec get_challenge() -> error|map().
get_challenge() ->
    case catch gen_fsm:sync_send_event({global, ?MODULE}, get_challenge) of
        % process not started, wrong state, ...
        {'EXIT', Exc} ->
            %io:format("exc: ~p~n", [Exc]),
            error;

        % challenge #{token => ..., thumbprint => ...}
        C -> C
    end.


%%
%% gen_server API
%%

idle(get_challenge, _, State) ->
    {reply, no_challenge, idle, State};

idle({create, Domain, Opts}, _, State=#state{key=Key, jws=JWS, acme_srv={_,_,_,BasePath}}) ->
    Conn  = get_conn(State),
    Nonce = get_nonce(Conn, State),
    SANs  = maps:get(san, Opts, []),

    Nonce2   = letsencrypt_api:new_reg(Conn, BasePath, Key, JWS#{nonce => Nonce}),
    {StateName, Reply, Nonce5, NChallenges} = case authz([Domain|SANs], State#state{conn=Conn, nonce=Nonce2}) of
        {error, Err, Nonce3} ->
            {idle, {error, Err}, Nonce3, undefined};

        {ok, Challenges, Nonce4} ->
            {pending, ok, Nonce4, Challenges}
    end,

    {reply, Reply, StateName, 
     State#state{conn=Conn, domain=Domain, nonce=Nonce5, challenge=NChallenges, sans=SANs}}.


pending(get_challenge, _, State=#state{challenge=Challenge}) ->
    {reply, Challenge, pending, State};

pending(Action, _, State=#state{challenge=Challenges}) ->
    Conn  = get_conn(State),

    % checking status for each domain name
    Reply = {StateName,_} = maps:fold(fun(_K, #{uri := Uri}, {Status,Msg}) ->
        {ok, {_,_,_,_,UriPath,_}} = http_uri:parse(str(Uri)),
        {Status2, Msg2} = letsencrypt_api:challenge(status, Conn, UriPath),
        %io:format("~p: ~p (~p)~n", [_K, Status2, Msg2]),

        case {Status, Status2} of
            {valid  ,   valid} -> {valid, Msg};
            {pending,       _} -> {pending, Msg};
            {_      , pending} -> {pending, Msg};
            {valid  , Status2} -> {Status2, Msg2};
            {Status ,       _} -> {Status, Msg}
        end
    end, {valid, undefined}, Challenges),

    %io:format(":: challenge state -> ~p~n", [Reply]),
    {reply, Reply, StateName, State#state{conn=Conn}}.


valid(_, _, State=#state{mode=Mode, domain=Domain, sans=SANs, cert_path=CertPath, key=Key, jws=JWS,
                             acme_srv={_,_,_,BasePath}, intermediate_cert=IntermediateCert}) ->

    challenge_destroy(Mode, State),

    Conn  = get_conn(State),
    Nonce = get_nonce(Conn, State),

    #{file := KeyFile} = letsencrypt_ssl:private_key({new, str(<<Domain/binary, ".key">>)}, CertPath),
    Csr = letsencrypt_ssl:cert_request(str(Domain), CertPath, SANs),

    {DomainCert, Nonce2} = letsencrypt_api:new_cert(Conn, BasePath, Key, JWS#{nonce => Nonce}, Csr),

    CertFile = letsencrypt_ssl:certificate(str(Domain), DomainCert, IntermediateCert, CertPath),

    {reply, {ok, #{key => bin(KeyFile), cert => bin(CertFile)}}, idle, State#state{conn=Conn, nonce=Nonce2}}.

%%%
%%% 
%%%

handle_event(reset, StateName, State=#state{mode=Mode}) ->
    %io:format("reset from ~p state~n", [StateName]),
    challenge_destroy(Mode, State),
    {next_state, idle, State};

handle_event(_, StateName, State) ->
    io:format("async evt: ~p~n", [StateName]),
    {next_state, StateName, State}.

handle_sync_event(stop,_,_,_) ->
    {stop, normal, ok, #state{}};
handle_sync_event(_,_, StateName, State) ->
    io:format("sync evt: ~p~n", [StateName]),
    {reply, ok, StateName, State}.

handle_info(_, StateName, State) ->
    {next_state, StateName, State}.

terminate(_,_,_) ->
    ok.

code_change(_, StateName, State, _) ->
    {ok, StateName, State}.

%%
%% PRIVATE funs
%%

-spec get_conn(state()) -> pid().
get_conn(#state{conn=undefined, acme_srv=AcmeSrv}) ->
    letsencrypt_api:connect(AcmeSrv);
get_conn(#state{conn=Conn}) ->
    Conn.


-spec get_nonce(pid(), state()) -> nonce().
get_nonce(Conn, #state{nonce=undefined, acme_srv={_,_,_,Path}}) ->
    letsencrypt_api:get_nonce(Conn, Path);
get_nonce(_, #state{nonce=Nonce}) ->
    Nonce.


authz(Domains, State=#state{mode=Mode}) ->
    case authz_step1(Domains, State, #{}) of
        {error, Err, Nonce} ->
            {error, Err, Nonce};

        {ok, Challenges, Nonce2} ->
            %io:format("challenges: ~p~n", [Challenges]),
            challenge_init(Mode, State, Challenges),

            case authz_step2(maps:to_list(Challenges), State#state{nonce=Nonce2}) of
                {ok, Nonce3} ->
                    {ok, Challenges, Nonce3};
                Err ->
                    Err
            end
    end.


authz_step1([], #state{nonce=Nonce}, Challenges) ->
    {ok, Challenges, Nonce};
authz_step1([Domain|T], State=#state{conn=Conn, nonce=Nonce, key=Key, jws=JWS,
                                              acme_srv={_,_,_,BasePath}},
                    Challenges) ->

    AuthzRet = letsencrypt_api:new_authz(Conn, BasePath, Key, JWS#{nonce => Nonce}, Domain),
    %io:format("authzret= ~p~n", [AuthzRet]),

    case AuthzRet of
        {error, Err, Nonce2} ->
            {error, Err, Nonce2};

        {ok, AuthzChallenge, Nonce3} ->
            ChallengeResponse = letsencrypt_api:challenge(pre, Conn, BasePath, Key, JWS, AuthzChallenge),

            %NOTE: keep <18.0 compatibility
            Challenges2 = maps:put(Domain, ChallengeResponse, Challenges),
            authz_step1(T, State#state{nonce=Nonce3}, Challenges2)
    end.


authz_step2([], #state{nonce=Nonce}) ->
    {ok, Nonce};
authz_step2([{Domain, Challenge}|T], State=#state{conn=Conn, nonce=Nonce, key=Key, jws=JWS,
                                                         acme_srv={Proto,AcmeDomain,AcmePort,_}}) ->

    #{uri := CUri, thumbprint := Thumbprint} = Challenge,
    % NOTE: we assume we are on same server than acme_srv, so we reuse Conn
    case http_uri:parse(str(CUri)) of
        % matching acme_srv proto, domain & port
        {ok, {Proto,_,AcmeDomain,AcmePort,CUriPath,_}} ->
            Nonce1 = letsencrypt_api:challenge(post, Conn, CUriPath, Key, JWS#{nonce => Nonce}, Thumbprint),

            authz_step2(T, State#state{nonce=Nonce1});

        _ ->
            {error, <<"invalid ", CUri/binary, " challenge uri">>, Nonce}
    end.
-spec challenge_init(mode(), state(), map()) -> ok.
challenge_init(webroot, #state{webroot_path=WPath}, Challenges) ->
    maps:fold(
        fun(_K, #{token := Token, thumbprint := Thumbprint}, _Acc) ->
            file:write_file(<<(bin(WPath))/binary, $/, ?WEBROOT_CHALLENGE_PATH/binary, $/, Token/binary>>,
                            Thumbprint)
        end,
        0, Challenges
    );
challenge_init(slave, _, _) ->
    ok;
challenge_init(standalone, #state{port=Port}, _) ->
	% be sure handler is not already running
	cowboy:stop_listener(letsencrypt_cowboy_listener),

    Dispatch = cowboy_router:compile([
        {'_', [{<<?WEBROOT_CHALLENGE_PATH/binary, "/:token">>, letsencrypt_cowboy_handler, []}]}
    ]),

    {ok, _} = cowboy:start_http(letsencrypt_cowboy_listener, 1,
		[{port, Port}],
        [{env, [{dispatch, Dispatch}]}]
    ),

    ok.


-spec challenge_destroy(mode(), state()) -> ok.
challenge_destroy(webroot, #state{webroot_path=WPath, challenge=Challenges}) ->
    maps:fold(fun(_K, #{token := Token}, _) ->
        file:delete(<<(bin(WPath))/binary, $/, ?WEBROOT_CHALLENGE_PATH/binary, $/, Token/binary>>)
    end, 0, Challenges),
    ok;
challenge_destroy(standalone, _) ->
	% stop http server
	cowboy:stop_listener(letsencrypt_cowboy_listener),
    ok;
challenge_destroy(slave, _) ->
	ok.


