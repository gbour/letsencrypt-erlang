
-module(slave).
-export([main/1, main/2, on_complete/1]).

on_complete({State, Data}) ->
    io:format("letsencrypt completed: ~p (data: ~p)~n", [State, Data]),
    % we can safely stop cowboy and letsencrypt service now
    cowboy:stop_listener(my_http_listener),
    letsencrypt:stop().

main(Domain) ->
    main(Domain, 80).

main(Domain, Port) ->
    application:ensure_all_started(letsencrypt),
    cowboy:stop_listener(my_http_listener),

    Dispatch = cowboy_router:compile([
        {'_', [
            {<<"/.well-known/acme-challenge/:token">>, letsencrypt_cowboy_handler, []}
        ]}
    ]),
    {ok, _} = cowboy:start_http(my_http_listener, 1, [{port, Port}],
        [{env, [{dispatch, Dispatch}]}]
    ),

    letsencrypt:start([{mode,slave}, staging, {cert_path, "/tmp"}]),
    letsencrypt:make_cert(Domain, #{callback => fun on_complete/1}),

    ok.
