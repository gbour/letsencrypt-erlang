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

-module(letsencrypt_elli_handler).
-behaviour(elli_handler).

-include_lib("elli/include/elli.hrl").
-export([handle/2, handle_event/3]).


handle(Req, Args) ->
    %io:format("Elli: ~p~n~p~n", [Req, Args]),
    handle(elli_request:method(Req), elli_request:path(Req), Req, Args).


handle('GET', [<<".well-known">>, <<"acme-challenge">>, Token], Req, [Thumbprints]) ->
    %NOTE: when testing on travis with local boulder instance, Host header may contain port number
    %      I dunno if it can happens againts production boulder, but this line filters it out
    [Host|_]   = binary:split(elli_request:get_header(<<"Host">>, Req, <<>>), <<":">>),
    %io:format("ELLI: host= ~p~n", [Host]),

    case maps:get(Host, Thumbprints, undefined) of
        #{Token := Thumbprint} ->
            %io:format("match: ~p -> ~p~n", [Token, Thumbprint]),
            {200, [{<<"Content-Type">>, <<"text/plain">>}], Thumbprint};

        _X     ->
            %io:format("nomatch: ~p -> ~p~n", [Token, _X]),
            {404, [], <<"Not Found">>}
    end.


% request events. Unused
handle_event(_, _, _) ->
    ok.
