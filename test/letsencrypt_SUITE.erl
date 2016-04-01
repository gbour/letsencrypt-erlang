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

-module(letsencrypt_SUITE).
-compile([export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(PORT, 5002).
-define(DEBUG(Fmt, Args), ct:log(default, 50, Fmt, Args)).


generate_groups([], Tests) ->
    Tests;
generate_groups([H|T], Tests) ->
    Sub = generate_groups(T, Tests),

    [ {Item, [], Sub} || Item <- H ].

groups() ->
    % we build a test matrix (combining all matrix items)
    Tests = [test_standalone, test_slave, test_webroot],
    Matrix = [
        ['dft-challenge', 'http-01']    % challenge type
        ,['dft-sync', 'async', 'sync']  % sync/async
        ,[unidomain, san]               % san or not
    ],

    Groups = generate_groups(Matrix, Tests),
    io:format("groups = ~p~n", [Groups]),
    [
        {matrix, [], Groups}
        ,{'tls-sni-01', [], [test_standalone]}
    ].

%        {simple, [], [
%            test_standalone
%            ,test_slave
%            ,test_webroot
%        ]},
%        {san, [], [
%            test_standalone
%            ,test_slave
%            ,test_webroot
%        ]},
%        {tlssni, [], [
%            test_standalone
%        }]
%    ].

all() ->
    [
        {group, matrix},
        {group, 'tls-sni-01'}
    ].


init_per_suite(Config) ->
    application:ensure_all_started(letsencrypt),
    [{opts, #{}}].


setopt(Config, Kv) ->
    Opts = proplists:get_value(opts, Config),
    lists:keyreplace(opts, 1, Config, {opts, maps:merge(Opts, Kv)}).

% challenge type (default: http-01)
init_per_group('dft-challenge', Config) ->
    [{port, 5002}|Config];
init_per_group('http-01', Config) ->
    [{port, 5002}| setopt(Config, #{challenge => 'http-01'})];
init_per_group('tls-sni-01', Config) ->
    [{port, 5001}| setopt(Config, #{challenge => 'tls-sni-01', async => false})];
% sync/async
init_per_group(sync, Config) ->
    setopt(Config, #{async => false});
init_per_group(async, Config) ->
    setopt(Config, #{async => true});
% unidomain/san
init_per_group(san, Config) ->
    setopt(Config, #{san => [<<"le2.wtf">>]});

init_per_group(_, Config)   ->
    Config.

end_per_group(_,_) ->
    ok.


test_standalone(Config) ->
    Port = proplists:get_value(port, Config),
    {ok, Pid} = letsencrypt:start([{mode, standalone}, staging, {port, Port}, {cert_path, "/tmp"}]),

    Opts = proplists:get_value(opts, Config),
    ?DEBUG("opts: ~p~n", [Opts]),
    case maps:get(async, Opts, true) of
        false ->
            {ok, #{cert := Cert, key := Key}} = letsencrypt:make_cert(<<"le.wtf">>, Opts);

        true  ->
            % async callback
            C = fun({Status, Result}) ->
                ok
            end,

            async = letsencrypt:make_cert(<<"le.wtf">>, Opts#{callback => C})
    end,

    letsencrypt:stop(),

    ok.

test_slave(Config) ->
    cowboy:stop_listener(my_http_listener),

    Dispatch = cowboy_router:compile([
        {'_', [
            {<<"/.well-known/acme-challenge/:token">>, letsencrypt_cowboy_handler, []}
        ]}
    ]),
    {ok, _} = cowboy:start_http(my_http_listener, 1, [{port, ?PORT}],
        [{env, [{dispatch, Dispatch}]}]
    ),


    {ok, Pid} = letsencrypt:start([{mode, slave}, staging, {cert_path, "/tmp"}]),

    Opts = proplists:get_value(opts, Config),
    %{ok, #{cert := Cert, key := Key}} = letsencrypt:make_cert(<<"le.wtf">>, Opts),
    letsencrypt:make_cert(<<"le.wtf">>, Opts),

    letsencrypt:stop(),
    cowboy:stop_listener(my_http_listener),

    ok.

test_webroot(Config) ->
    cowboy:stop_listener(webroot_listener),

    % use cowboy to serve acme challenge file
    Dispatch = cowboy_router:compile([
        {'_', [
            {<<"/.well-known/acme-challenge/:token">>, test_webroot_handler, []}
        ]}
    ]),
    {ok, _} = cowboy:start_http(my_http_listener, 1, [{port, ?PORT}],
        [{env, [{dispatch, Dispatch}]}]
    ),

    {ok, Pid} = letsencrypt:start([{mode, webroot}, staging, {webroot_path, "/tmp"}, {cert_path, "/tmp"}]),

    Opts = proplists:get_value(opts, Config),
    %{ok, #{cert := Cert, key := Key}} = letsencrypt:make_cert(<<"le.wtf">>, SAN#{async => false}),
    letsencrypt:make_cert(<<"le.wtf">>, Opts),

    letsencrypt:stop(),
    cowboy:stop_listener(my_http_listener),

    ok.


