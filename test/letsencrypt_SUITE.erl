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

-define(DEBUG(Str), ct:log(default, 50, Str++"~n", [])).
-define(DEBUG(Fmt, Args), ct:log(default, 50, Fmt++"~n", Args)).


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
    [{port, 5002},{filter, 'dft-challenge'}| Config];
init_per_group('http-01', Config) ->
    [{port, 5002},{filter, 'http-01'}| setopt(Config, #{challenge => 'http-01'})];
init_per_group('tls-sni-01', Config) ->
    [{port, 5001},{filter,'tls-sni-01'}| setopt(Config, #{challenge => 'tls-sni-01', async => true})];
% sync/async
init_per_group(sync, Config) ->
    [{filter, sync}| setopt(Config, #{async => false})];
init_per_group(async, Config) ->
    [{filter, async}| setopt(Config, #{async => true})];
% unidomain/san
init_per_group(N=san, Config) ->
    [{filler, san}| setopt(Config, #{san => [<<"le2.wtf">>]})];

init_per_group(GroupName, Config)   ->
    [{filter,GroupName}| Config].

end_per_group(_,_) ->
    ok.


test_standalone(Config) ->
    Port  = proplists:get_value(port, Config),
    priv_COMMON(standalone, Config, [{port,Port}]).

test_slave(Config) ->
    Port = proplists:get_value(port, Config),
    cowboy:stop_listener(my_http_listener),

    Dispatch = cowboy_router:compile([
        {'_', [
            {<<"/.well-known/acme-challenge/:token">>, letsencrypt_cowboy_handler, []}
        ]}
    ]),
    {ok, _} = cowboy:start_http(my_http_listener, 1, [{port, Port}],
        [{env, [{dispatch, Dispatch}]}]
    ),

    priv_COMMON(slave, Config, []),
    cowboy:stop_listener(my_http_listener).

test_webroot(Config) ->
    Port = proplists:get_value(port, Config),
    cowboy:stop_listener(webroot_listener),

    % use cowboy to serve acme challenge file
    Dispatch = cowboy_router:compile([
        {'_', [
            {<<"/.well-known/acme-challenge/:token">>, test_webroot_handler, []}
        ]}
    ]),
    {ok, _} = cowboy:start_http(my_http_listener, 1, [{port, Port}],
        [{env, [{dispatch, Dispatch}]}]
    ),

    priv_COMMON(webroot, Config, [{webroot_path, "/tmp"}]),
    cowboy:stop_listener(my_http_listener).

%%
%% PRIVATE
%%


priv_COMMON(Mode, Config, StartOpts) ->
    Comment = string:join(lists:map(fun erlang:atom_to_list/1, proplists:get_all_values(filter, Config)), ","),
    ct:comment(Comment, []),

    Opts  = proplists:get_value(opts, Config),
    Async = maps:get(async, Opts, true),
    ?DEBUG("async: ~p, opts: ~p, startopts: ~p", [Async, Opts, StartOpts]),

    {ok, Pid} = letsencrypt:start([{mode, Mode}, staging, {cert_path, "/tmp"}]++StartOpts),

    R3 = case Async of
        false ->
            letsencrypt:make_cert(<<"le.wtf">>, Opts);

        true  ->
            % async callback
            Parent = self(),
            C = fun(R) ->
                Parent ! {complete, R}
            end,

            async = letsencrypt:make_cert(<<"le.wtf">>, Opts#{callback => C}),
            receive
                {complete, R2} -> R2
                after 60000    -> {error, async_timeout}
            end
    end,

    letsencrypt:stop(),
    % checking certificate returned
    ?DEBUG("result: ~p", [R3]),
    {ok, #{cert := Cert, key := Key}} = R3,

    ok.

