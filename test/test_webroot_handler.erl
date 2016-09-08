
-module(test_webroot_handler).
-export([init/3, handle/2, terminate/3]).

init(_, Req, []) ->
    {Path, _} = cowboy_req:path(Req),
    File = <<"/tmp", Path/binary>>,
    io:format("reading ~p~n", [File]),

    Req2 = case file:read_file(File) of
        {ok, Content} ->
            cowboy_req:reply(200, [{<<"content-type">>, <<"text/plain">>}], Content, Req);

        _ ->
            cowboy_req:reply(404, Req)
    end,

    {ok, Req2, no_state}.

handle(Req, State) ->
    {ok, Req, State}.

terminate(_Reason, _Req, _State) ->
    ok.
