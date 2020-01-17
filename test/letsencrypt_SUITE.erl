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

-module(letsencrypt_SUITE).
-compile([export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-include_lib("public_key/include/public_key.hrl").

-define(DEBUG(Str), ct:log(default, 50, Str++"~n", [])).
-define(DEBUG(Fmt, Args), ct:log(default, 50, Fmt++"~n", Args)).

-define(HOSTNAME, <<"le.wtf">>).
-define(HOSTNAME2, <<"le2.wtf">>).
-define(FAKE_CA, "Pebble Intermediate CA 60eec7").

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

end_per_suite(Config) ->
	application:stop(letsencrypt),
	ok.

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
    [{filler, san}| setopt(Config, #{san => [?HOSTNAME2]})];

init_per_group(GroupName, Config)   ->
    [{filter,GroupName}| Config].

end_per_group(_,_) ->
    ok.


test_standalone(Config) ->
    Port  = proplists:get_value(port, Config),
    priv_COMMON(standalone, Config, [{port,Port}]).

test_slave(Config) ->
    Port = proplists:get_value(port, Config),
    %cowboy:stop_listener(my_http_listener),
    elli:start_link([
        {name    , {local, my_test_slave_listener}},
        {callback, letsencrypt_elli_handler},
        {port    , Port}
    ]),

    try priv_COMMON(slave, Config, []) of
        Ret -> Ret
    after
        elli:stop(my_test_slave_listener)
    end.

test_webroot(Config) ->
    Port = proplists:get_value(port, Config),
    %cowboy:stop_listener(webroot_listener),

    elli:start_link([
        {name    , {local, my_test_webroot_listener}},
        {callback, test_webroot_handler},
        {port    , Port}
    ]),

    try priv_COMMON(webroot, Config, [{webroot_path, "/tmp"}]) of
        Ret -> Ret
    after
        elli:stop(my_test_webroot_listener)
    end.

%%
%% PRIVATE
%%


priv_COMMON(Mode, Config, StartOpts) ->
    Comment = string:join(lists:map(fun erlang:atom_to_list/1, proplists:get_all_values(filter, Config)), ","),
    ct:comment(Comment, []),
    ct:print("%%% letsencrypt_SUITE <== test_"++erlang:atom_to_list(Mode)++": "++Comment),

    Opts  = proplists:get_value(opts, Config),
    Async = maps:get(async, Opts, true),
    ?DEBUG("async: ~p, opts: ~p, startopts: ~p", [Async, Opts, StartOpts]),

    {ok, Pid} = letsencrypt:start([{mode, Mode}, staging, {cert_path, "/tmp"}]++StartOpts),

    R3 = case Async of
        false ->
            letsencrypt:make_cert(?HOSTNAME, Opts);

        true  ->
            % async callback
            Parent = self(),
            C = fun(R) ->
                Parent ! {complete, R}
            end,

            async = letsencrypt:make_cert(?HOSTNAME, Opts#{callback => C}),
            receive
                {complete, R2} -> R2
                after 60000    -> {error, async_timeout}
            end
    end,

    letsencrypt:stop(),
    % checking certificate returned
    ?DEBUG("result: ~p", [R3]),
    {ok, #{cert := Cert, key := Key}} = R3,
    certificate_validation(Cert, ?HOSTNAME, maps:get(san, Opts, [])),

    ok.

certificate_validation(CertFile, Domain, SAN) ->
    {ok, File} = file:read_file(CertFile),
    [{'Certificate',Cert,_}|_] = public_key:pem_decode(File), % 2d certificate is letsencrypt intermediate's one

    #'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{
        issuer = Issuer,
        validity = #'Validity'{notBefore = Start, notAfter= End},
        subject = Subject,
        extensions = Exts
    }} = public_key:pkix_decode_cert(Cert, otp),

    ?DEBUG("== certificate informations ==~n"++
           " > subject: ~p~n"++
           " > issuer : ~p~n"++
           " > start/stop: ~p/~p~n" ++
           " > altNames: ~p~n",
           [rdnSeq(Subject, ?'id-at-commonName'), rdnSeq(Issuer, ?'id-at-commonName'),
            to_date(Start), to_date(End), exten(Exts, ?'id-ce-subjectAltName')]),

    % performing match tests
    startswith(rdnSeq(Issuer , ?'id-at-commonName'), ?FAKE_CA, "wrong issuer (~p =:= ~p)"),
    match(rdnSeq(Subject, ?'id-at-commonName'), erlang:binary_to_list(Domain), "wrong CN (~p =:= ~p)"),

    SAN2 = [ erlang:binary_to_list(X) || X <- [Domain|SAN] ],
    match(exten(Exts, ?'id-ce-subjectAltName'), SAN2, "wrong SAN (~p =:= ~p)"),

    % certificate validity = 90 days
    match(add_days(to_date(Start), 90), to_date(End), "wrong certificate validity (~p =:= ~p)"),

    ok.

rdnSeq({rdnSequence, Seq}, Match) ->
    rdnSeq(Seq, Match);
rdnSeq([[{'AttributeTypeAndValue', Match, Result}]|_], Match) ->
    str(Result);
rdnSeq([H|T], Match) ->
    rdnSeq(T, Match);
rdnSeq([], _) ->
    undefined.

exten([], Match) ->
    undefined;
exten([#'Extension'{extnID = Match, extnValue = Values}|_], Match) ->
    [ str(DNS) || DNS <- Values];
exten([H|T], Match) ->
    exten(T, Match).

str({printableString, Str}) ->
    Str;
str({utf8String, Str}) ->
	erlang:binary_to_list(Str);
str({dNSName, Str}) ->
    Str.

to_date({utcTime, Date}) ->
    case re:run(Date, "(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})Z",[{capture,all_but_first,list}]) of
        {match, Matches} ->
            [Y,M,D,H,Mm,S] = lists:map(fun(X) -> erlang:list_to_integer(X) end, Matches),
            {{2000+Y, M, D}, {H, Mm, S}};

        _ -> error
    end.

add_days({Date,Time}, Days) ->
    {
        calendar:gregorian_days_to_date(
            calendar:date_to_gregorian_days(Date) + Days),
        Time
    }.

match(X, Y, Msg) ->
    case X =:= Y of
        false ->
            ?DEBUG(Msg, [X,Y]),
            throw({'match-exception', lists:flatten(io_lib:format(Msg, [X,Y]))});

        _ -> true
    end.

startswith(X, Y, Msg) ->
	case string:slice(X, 0, string:len(Y)) of
		false ->
            ?DEBUG(Msg, [X,Y]),
            throw({'match-exception', lists:flatten(io_lib:format(Msg, [X,Y]))});

        _ -> true
	end.
