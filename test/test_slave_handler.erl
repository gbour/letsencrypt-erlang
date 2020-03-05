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

-module(test_slave_handler).
-behaviour(elli_handler).

-include_lib("elli/include/elli.hrl").
-export([handle/2, handle_event/3]).


handle(Req, _Args) ->
	[<<".well-known">>, <<"acme-challenge">>, Token] = elli_request:path(Req),
	[Host|_]   = binary:split(elli_request:get_header(<<"Host">>, Req, <<>>), <<":">>),
	Thumbprints = letsencrypt:get_challenge(),
	io:format("SLAVE:handle: req=~p, host= ~p, thumbprints= ~p~n", [Req, Host, Thumbprints]),

	case maps:get(Token, Thumbprints, nil) of
		Thumbprint ->
			io:format("200: ~p~n", [Thumbprint]),
			{200, [{<<"Content-Type">>, <<"text/plain">>}], Thumbprint};

		_ ->
			io:format("404~n", []),
			{404, [], <<"Not Found">>}
	end.

% request events. Unused
handle_event(_, _, _) ->
    ok.
