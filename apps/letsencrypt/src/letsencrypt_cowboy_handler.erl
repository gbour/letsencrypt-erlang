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

-module(letsencrypt_cowboy_handler).

-export([init/2]).


init(Req, []) ->
    %io:format("req ~p~n", [Req]),

    % NOTES
    %   - cowboy_req:binding() returns undefined is token not set in URI
    %   - letsencrypt:get_challenge() returns 'error' if token+thumbprint are not available
    %
    Req2 = case {cowboy_req:binding(token, Req), letsencrypt:get_challenge()} of
       {Token, #{token := Token, thumbprint := Thumbprint}} ->
            %io:format("match: ~p -> ~p~n", [Token, Thumbprint]),
            cowboy_req:reply(200, [{<<"content-type">>, <<"text/plain">>}], Thumbprint, Req);

        _X     ->
            %io:format("nomatch: ~p~n", [_X]),
            cowboy_req:reply(404, Req)
    end,

    {ok, Req2, []}.

