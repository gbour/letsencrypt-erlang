
-module(test_webroot_handler).
-export([init/2]).

init(Req, []) ->
    File = <<"/tmp", (cowboy_req:path(Req))/binary>>,
    io:format("reading ~p~n", [File]),

    Req2 = case file:read_file(File) of
        {ok, Content} ->
            cowboy_req:reply(200, [{<<"content-type">>, <<"text/plain">>}], Content, Req);

        _ ->
            cowboy_req:reply(404, Req)
    end,

    {ok, Req2, []}.
