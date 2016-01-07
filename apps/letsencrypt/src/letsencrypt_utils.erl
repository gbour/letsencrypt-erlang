%% Copyright 2015 Guillaume Bour
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

-module(letsencrypt_utils).
-author("Guillaume Bour <guillaume@bour.cc>").

-export([b64encode/1]).

-type character() :: integer().

-spec b64encode(string()|binary()) -> binary().
b64encode(X) ->
    Base64 = base64:encode(X),
    << <<(encode_byte(B)):8>> || <<B:8>> <= Base64, B =/= $= >>.

-spec encode_byte(character()) -> character().
encode_byte($+) -> $-;
encode_byte($/) -> $_;
encode_byte(B) -> B.

