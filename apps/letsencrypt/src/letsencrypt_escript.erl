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

-module(letsencrypt_escript).
-author("Guillaume Bour <guillaume@bour.cc>").

-export([main/1]).


main([Domain]) ->
    application:ensure_all_started(letsencrypt),

    io:format("querying letsencrypt certificate for '~p' domain~n", [Domain]),
    os:cmd("mkdir -p /tmp/letsencrypt/certs"),

    letsencrypt:start([{mode,standalone},staging,{port, 8000},{cert_path,"/tmp/letsencrypt/certs"}]),
    letsencrypt:make_cert(Domain, #{async => false}),
    letsencrypt:stop(),

    halt(1).
