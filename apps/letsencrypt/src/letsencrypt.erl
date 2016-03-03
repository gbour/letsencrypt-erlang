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

-module(letsencrypt).
-author("Guillaume Bour <guillaume@bour.cc>").
-behaviour(gen_fsm).

-export([make_cert/2, make_cert_bg/2]).
-export([start/1, stop/0, init/1, handle_event/3, handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).
-export([idle/3, pending/3, valid/3]).

% uri format compatible with shotgun library
-type uri()            :: {Host::string(), Port::integer(), Path::string()}.
-type nonce()          :: binary().
-type jws()            :: #{'alg' => 'RS256', 'jwk' => map(), nonce => undefined|letsencrypt:nonce() }.
-type ssl_privatekey() :: #{'raw' => crypto:rsa_private(), 'b64' => {binary(), binary()}, 'file' => string()}.
-type ssl_csr()        :: binary().



-define(STAGING_API_URL, {"acme-staging.api.letsencrypt.org", 443, "/acme/"}).
-define(DEFAULT_API_URL, {"acme-v01.api.letsencrypt.org"    , 443, "/acme/"}).
-define(AGREEMENT_URL  , <<"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf">>).
-define(INTERMEDIATE_CERT_URL, {"letsencrypt.org", 443, "/certs/lets-encrypt-x1-cross-signed.pem"}).

-define(WEBROOT_CHALLENGE_PATH, "/.well-known/acme-challenge/").

-record(state, {
    acme_srv = ?DEFAULT_API_URL     :: uri(),
    key_file  = undefined           :: undefined | string(),
    cert_path = "/tmp"              :: string(),

    mode = undefined                :: undefined | webroot,
    % mode = webroot
    webroot_path = undefined        :: undefined | string(),

    intermediate_cert = undefined   :: undefined | binary(),

    % state datas
    conn  = undefined               :: undefined | pid(),
    nonce = undefined               :: undefined | nonce(),
    domain = undefined              :: undefined | binary(),
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
    gen_fsm:stop({global, ?MODULE}).

%%
%% Args:
%%   staging
-spec init(list( atom() | {atom(),any()} )) -> {ok, idle, state()}.
init(Args) ->
    {Args2, State} = mode_opts(proplists:get_value(mode, Args), Args),
    State2 = getopts(Args2, State),
    %io:format("state= ~p~n", [State2]),

    % loading private key into memory
    Key = letsencrypt_ssl:private_key(State2#state.key_file, State2#state.cert_path),
    Jws = letsencrypt_jws:init(Key),

    {ok, IntermediateCert} = letsencrypt_api:get_intermediate(?INTERMEDIATE_CERT_URL),

    {ok, idle, State2#state{key=Key, jws=Jws, intermediate_cert=IntermediateCert}}.

-spec mode_opts(webroot, list(atom()|{atom(),any()})) -> {list(atom()|{atom(),any()}), state()}.
mode_opts(Mode, Args) ->
    mode_opts(Mode, proplists:delete(mode, Args), #state{mode=Mode}).

-spec mode_opts(webroot, list(atom()|{atom(),any()}), state()) -> {list(atom()|{atom(),any()}), state()}.
mode_opts(webroot, [{webroot_path, Path}|Args], State) ->
    %TODO: check directory is writeable
    os:cmd("mkdir -p '"++ Path ++ ?WEBROOT_CHALLENGE_PATH ++ "'"),

    mode_opts(webroot, Args, State#state{webroot_path=Path});
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
    gen_fsm:sync_send_event({global, ?MODULE}, {create, bin(Domain), Opts}, 15000),
    Ret = case wait_valid(10) of
        ok ->
            gen_fsm:sync_send_event({global, ?MODULE}, finalize, 15000);

        Error ->
            gen_fsm:send_all_state_event({global, ?MODULE}, reset),
            Error
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
    {error, pending};
wait_valid(Cnt,Max) ->
    case gen_fsm:sync_send_event({global, ?MODULE}, check, 15000) of
        valid   -> ok;
        pending ->
            timer:sleep(500*(Max-Cnt+1)),
            wait_valid(Cnt-1,Max);
        Status  -> {error, Status}
    end.


%%
%% gen_server API
%%

idle({create, Domain, _Opts}, _, 
        State=#state{mode=webroot, webroot_path=WPath, key=Key, jws=JWS, acme_srv={AcmDomain,_,BasePath}}) ->
    Conn  = get_conn(State),
    Nonce = get_nonce(Conn, State),

    Nonce2 = letsencrypt_api:new_reg(Conn, BasePath, Key, JWS#{nonce => Nonce}),
    {HttpChallenge, Nonce3} = letsencrypt_api:new_authz(Conn, BasePath, Key, JWS#{nonce => Nonce2}, Domain),
    ChallengeResponse = letsencrypt_api:challenge(pre, Conn, BasePath, Key, JWS, HttpChallenge),
    
    #{token := CFile, thumbprint := Thumbprint} = ChallengeResponse,
    CPath = <<(bin(?WEBROOT_CHALLENGE_PATH))/binary, $/, CFile/binary>>,
    %io:format("file= ~p, content= ~p~n", [CPath, Thumbprint]),
    file:write_file(<<(bin(WPath))/binary, $/, CPath/binary>>, Thumbprint),

    #{<<"uri">> := CUri} = HttpChallenge,

    BAcmDomain = bin("https://"++AcmDomain),
    LAcmDomain = length("https://"++AcmDomain),
    <<BAcmDomain:LAcmDomain/binary, AcmPath/binary>> = CUri,

    Nonce4 = letsencrypt_api:challenge(post, Conn, str(AcmPath), Key, JWS#{nonce => Nonce3}, Thumbprint),

    {reply, CPath, pending, State#state{conn=Conn, domain=Domain, nonce=Nonce4, challenge=ChallengeResponse#{uri => CUri}}}.

pending(_, _, State=#state{challenge=#{uri := CUri}, acme_srv={AcmDomain,_,_}}) ->
    Conn  = get_conn(State),
    %Nonce = get_nonce(Conn, State),

    BAcmDomain = bin("https://"++AcmDomain),
    LAcmDomain = length("https://"++AcmDomain),
    <<BAcmDomain:LAcmDomain/binary, AcmPath/binary>> = CUri,

    {ok, Status, _Nonce2} = letsencrypt_api:challenge(status, Conn, str(AcmPath)),
    %io:format(":: pending -> ~p (~p)~n", [Status, AcmPath]),

    {reply, Status, Status, State#state{conn=Conn}}.

valid(_, _, State=#state{mode=webroot, domain=Domain, cert_path=CertPath, key=Key, jws=JWS,
                             acme_srv={_,_,BasePath}, intermediate_cert=IntermediateCert}) ->

    Conn  = get_conn(State),
    Nonce = get_nonce(Conn, State),

    #{file := KeyFile} = letsencrypt_ssl:private_key({new, str(<<Domain/binary, ".key">>)}, CertPath),
    Csr = letsencrypt_ssl:cert_request(str(Domain), CertPath), 

    {DomainCert, Nonce2} = letsencrypt_api:new_cert(Conn, BasePath, Key, JWS#{nonce => Nonce}, Csr),

    CertFile = letsencrypt_ssl:certificate(str(Domain), DomainCert, IntermediateCert, CertPath),

    {reply, {ok, #{key => bin(KeyFile), cert => bin(CertFile)}}, idle, State#state{conn=Conn, nonce=Nonce2}}.

%handle_call({create, Domain, Opts}, _, State) ->
%    Conn = get_conn(State),
%    Nonce = get_nonce(State),
%
%
%    {reply, ok, State#state{conn=Conn}};

handle_event(reset, StateName, State) ->
    %io:format("reset from ~p state~n", [StateName]),
    {next_state, idle, State};

handle_event(_, StateName, State) ->
    io:format("async evt: ~p~n", [StateName]),
    {next_state, StateName, State}.


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
get_nonce(Conn, #state{nonce=undefined, acme_srv=AcmeSrv}) ->
    letsencrypt_api:get_nonce(Conn, AcmeSrv);
get_nonce(_, #state{nonce=Nonce}) ->
    Nonce.


-spec bin(binary()|string()) -> binary().
bin(X) when is_binary(X) ->
    X;
bin(X) when is_list(X) ->
    list_to_binary(X);
bin(_X) ->
    throw(invalid).

-spec str(binary()) -> string().
str(X) when is_binary(X) ->
    binary_to_list(X);
str(_X) ->
    throw(invalid).

