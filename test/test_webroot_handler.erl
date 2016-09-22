
-module(test_webroot_handler).
-behaviour(elli_handler).

-include_lib("elli/include/elli.hrl").
-export([handle/2, handle_event/3]).


handle(Req, _Args) ->
    {Path, _} = elli_request:raw_path(Req),
    File = <<"/tmp", Path/binary>>,
    io:format("reading ~p~n", [File]),

    case file:read_file(File) of
        {ok, Content} ->
            {200, [{<<"Content-Type">>, <<"text/plain">>}], Content};

        _ ->
            {404, [], <<"Not Found">>}
    end.


% request events. Unused
handle_event(_, _, _) ->
    ok.
