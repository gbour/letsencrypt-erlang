
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

