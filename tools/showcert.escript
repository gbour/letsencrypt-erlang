#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp enable -sname showcert debug verbose

-include_lib("public_key/include/public_key.hrl").

main([CertFile]) ->
    {ok, File} = file:read_file(CertFile),
    [Cert|_] = public_key:pem_decode(File),
    %io:format("> ~p~n", [Cert]),

    {'Certificate',Cert2,not_encrypted} = Cert,
    {'OTPCertificate', Cert3, _, _} = public_key:pkix_decode_cert(Cert2, otp),
    io:format("*** RAW CERTIFICATE ***~n~p~n~n", [Cert3]),

    #'OTPTBSCertificate'{issuer = Issuer,  validity = #'Validity'{notBefore = Start, notAfter= End}, subject = Subject, extensions = Exts} = Cert3,
    io:format("*** CERTIFICATE NFOs ***\n"++
        "> subject   : ~p~n"++
        "> issuer    : ~p~n"++
        "> start/stop: ~p/~p (duration: ~p days)~n"++
        "> altNames  : ~p~n~n",
    [
        rdnSeq(Subject, ?'id-at-commonName'),
        rdnSeq(Issuer , ?'id-at-commonName'),
        iso_8601_fmt(to_date(Start)), 
        iso_8601_fmt(to_date(End)),
		diff(to_date(Start), to_date(End)),
        exten(Exts, ?'id-ce-subjectAltName')
    ]),
   
    to_date(End) =:= add_days(to_date(Start), 90), 
    ok;

main(_) ->
    io:format("Usage: showcert.escript certificate-file~n"),
    halt(1).


rdnSeq({rdnSequence, Seq}, Match) ->
    rdnSeq(Seq, Match);
rdnSeq([[{'AttributeTypeAndValue', Match, Result}]|_], Match) ->
    str(Result);
rdnSeq([_|T], Match) ->
    rdnSeq(T, Match);
rdnSeq([], _) ->
    undefined.

exten([], _Match) ->
    undefined;
exten([#'Extension'{extnID = Match, extnValue = Values}|_], Match) ->
    [ str(DNS) || DNS <- Values];
exten([_|T], Match) ->
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

diff({Date1,_}, {Date2,_}) ->
	calendar:date_to_gregorian_days(Date2) - calendar:date_to_gregorian_days(Date1).

iso_8601_fmt(DateTime) ->
    {{Year,Month,Day},{Hour,Min,Sec}} = DateTime,
    lists:flatten(io_lib:format("~4.10.0B-~2.10.0B-~2.10.0B ~2.10.0B:~2.10.0B:~2.10.0B",
        [Year, Month, Day, Hour, Min, Sec])).
