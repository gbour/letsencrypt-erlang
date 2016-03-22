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


groups() ->
    [
        {simple, [], [
            test_standalone
            ,test_slave
            ,test_webroot
        ]},
        {san, [], [
            test_standalone
            ,test_slave
            ,test_webroot
        ]}
    ].

all() ->
    [
        {group, simple},
        {group, san}
    ].

init_per_group(san, Config) ->
    [{san, #{domains => [<<"le2.wtf">>]}} |Config];
init_per_group(_, Config)   ->
    Config.

end_per_group(_,_) ->
    ok.


test_standalone(Config) ->
    application:ensure_all_started(letsencrypt),

    {ok, Pid} = letsencrypt:start([{mode, standalone}, staging, {port, 5002}, {cert_path, "/tmp"}]),

    SAN = proplists:get_value(san, Config, #{}),
    {ok, #{cert := Cert, key := Key}} = letsencrypt:make_cert(<<"le.wtf">>, SAN#{async => false}),
    %NOTE: is throwing a noproc exception, don't know why
    catch letsencrypt:stop(),

    ok.

test_slave(Config) ->
    application:ensure_all_started(letsencrypt),
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

    SAN = proplists:get_value(san, Config, #{}),
    {ok, #{cert := Cert, key := Key}} = letsencrypt:make_cert(<<"le.wtf">>, SAN#{async => false}),

    %NOTE: is throwing a noproc exception, don't know why
    catch letsencrypt:stop(),
    cowboy:stop_listener(my_http_listener),

    ok.

test_webroot(Config) ->
    application:ensure_all_started(letsencrypt),
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

    SAN = proplists:get_value(san, Config, #{}),
    {ok, #{cert := Cert, key := Key}} = letsencrypt:make_cert(<<"le.wtf">>, SAN#{async => false}),

    %NOTE: is throwing a noproc exception, don't know why
    catch letsencrypt:stop(),
    cowboy:stop_listener(my_http_listener),

    ok.


