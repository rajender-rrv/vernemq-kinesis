%%%-------------------------------------------------------------------
%%% @author user
%%% @copyright (C) 2019, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 22. Jul 2019 1:04 PM
%%%-------------------------------------------------------------------
-module(utils).
-author("user").
-include("myplugin.hrl").

-export([
  sign_v4_headers/5,
  sign_v4/8,
  headers/3,
  update_config/1,
  get_timeout/1
]).

-define(ERLCLOUD_RETRY_TIMEOUT, 10000).

%% API

headers(Config, Operation, Body) ->
  Headers = [{"host", Config#aws_config.kinesis_host},
    {"x-amz-target", Operation}],
  sign_v4_headers(Config, Headers, Body, Config#aws_config.aws_region, "kinesis").
%% http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

sign_v4_headers(Config, Headers, Payload, Region, Service) ->
  sign_v4(post, "/", Config, Headers, Payload, Region, Service, []).

sign_v4(Method, Uri, Config, Headers, Payload, Region, Service, QueryParams) ->
  Date = iso_8601_basic_time(),
  {PayloadHash, Headers1} =
    sign_v4_content_sha256_header([{"x-amz-date", Date} | Headers], Payload),
  Headers2 = case Config#aws_config.security_token of
               undefined -> Headers1;
               Token -> [{"x-amz-security-token", Token} | Headers1]
             end,
  {Request, SignedHeaders} = canonical_request(Method, Uri, QueryParams, Headers2, PayloadHash),
  CredentialScope = credential_scope(Date, Region, Service),
  ToSign = to_sign(Date, CredentialScope, Request),
  SigningKey = signing_key(Config, Date, Region, Service),
  Signature = base16(sha256_mac(SigningKey, ToSign)),
  Authorization = authorization(Config, CredentialScope, SignedHeaders, Signature),
  [{"Authorization", lists:flatten(Authorization)} | Headers2].

iso_8601_basic_time() ->
  {{Year, Month, Day}, {Hour, Min, Sec}} = calendar:universal_time(),
  lists:flatten([
    integer_to_list(Year), two_digits(Month), two_digits(Day), $T,
    two_digits(Hour), two_digits(Min), two_digits(Sec), $Z
  ]).

two_digits(Int) when Int < 10 ->
  [$0, $0 + Int];
two_digits(Int) ->
  integer_to_list(Int).

canonical_request(Method, CanonicalURI, QParams, Headers, PayloadHash) ->
  {CanonicalHeaders, SignedHeaders} = canonical_headers(Headers),
  CanonicalQueryString = canonical_query_string(QParams),
  {[string:to_upper(atom_to_list(Method)), $\n,
    CanonicalURI, $\n,
    CanonicalQueryString, $\n,
    CanonicalHeaders, $\n,
    SignedHeaders, $\n,
    PayloadHash],
    SignedHeaders}.


canonical_headers(Headers) ->
  Normalized = [{string:to_lower(Name), trimall(Value)} || {Name, Value} <- Headers],
  Sorted = lists:keysort(1, Normalized),
  Canonical = [[Name, $:, Value, $\n] || {Name, Value} <- Sorted],
  Signed = string:join([Name || {Name, _} <- Sorted], ";"),
  {Canonical, Signed}.

sign_v4_content_sha256_header(Headers, Payload) ->
  case proplists:get_value("x-amz-content-sha256", Headers) of
    undefined ->
      PayloadHash = hash_encode(Payload),
      NewHeaders = [{"x-amz-content-sha256", PayloadHash} | Headers],
      {PayloadHash, NewHeaders};
    PayloadHash -> {PayloadHash, Headers}
  end.

canonical_query_string([]) ->
  "";
canonical_query_string(Params) ->
  Normalized = [{url_encode(Name), url_encode(value_to_string(Value))} || {Name, Value} <- Params],
  Sorted = lists:keysort(1, Normalized),
  string:join([case Value of
                 [] -> [Key, "="];
                 _ -> [Key, "=", Value]
               end
    || {Key, Value} <- Sorted, Value =/= none, Value =/= undefined], "&").

trimall(Value) ->
  re:replace(Value, "(^\\s+)|(\\s+$)", "", [global]).

hash_encode(Data) ->
  Hash = sha256(Data),
  base16(Hash).

base16(Data) ->
  [binary:bin_to_list(base16:encode(Data))].

credential_scope(Date, Region, Service) ->
  DateOnly = string:left(Date, 8),
  [DateOnly, $/, Region, $/, Service, "/aws4_request"].

to_sign(Date, CredentialScope, Request) ->
  ["AWS4-HMAC-SHA256\n",
    Date, $\n,
    CredentialScope, $\n,
    hash_encode(Request)].

signing_key(Config, Date, Region, Service) ->
  DateOnly = string:left(Date, 8),
  KDate = sha256_mac("AWS4" ++ Config#aws_config.secret_access_key, DateOnly),
  KRegion = sha256_mac(KDate, Region),
  KService = sha256_mac(KRegion, Service),
  sha256_mac(KService, "aws4_request").

authorization(Config, CredentialScope, SignedHeaders, Signature) ->
  ["AWS4-HMAC-SHA256"
  " Credential=", Config#aws_config.access_key_id, $/, CredentialScope, $,,
    " SignedHeaders=", SignedHeaders, $,,
    " Signature=", Signature].

update_config(Config) ->
  {ok, Config}.


%%sha_mac(K, S) ->
%%  crypto:hmac(sha, K, S).


sha256_mac(K, S) ->
  crypto:hmac(sha256, K, S).

sha256(V) ->
  crypto:hash(sha256, V).

%%md5(V) ->
%%  crypto:hash(md5, V).

url_encode(Binary) when is_binary(Binary) ->
  url_encode(unicode:characters_to_list(Binary));
url_encode(String) ->
  url_encode(String, []).
url_encode([], Accum) ->
  lists:reverse(Accum);
url_encode([Char | String], Accum)
  when Char >= $A, Char =< $Z;
  Char >= $a, Char =< $z;
  Char >= $0, Char =< $9;
  Char =:= $-; Char =:= $_;
  Char =:= $.; Char =:= $~ ->
  url_encode(String, [Char | Accum]);
url_encode([Char | String], Accum) ->
  url_encode(String, utf8_encode_char(Char) ++ Accum).

utf8_encode_char(Char) when Char > 16#FFFF, Char =< 16#10FFFF ->
  encode_char(Char band 16#3F + 16#80)
  ++ encode_char((16#3F band (Char bsr 6)) + 16#80)
    ++ encode_char((16#3F band (Char bsr 12)) + 16#80)
    ++ encode_char((Char bsr 18) + 16#F0);
utf8_encode_char(Char) when Char > 16#7FF, Char =< 16#FFFF ->
  encode_char(Char band 16#3F + 16#80)
  ++ encode_char((16#3F band (Char bsr 6)) + 16#80)
    ++ encode_char((Char bsr 12) + 16#E0);
utf8_encode_char(Char) when Char > 16#7F, Char =< 16#7FF ->
  encode_char(Char band 16#3F + 16#80)
  ++ encode_char((Char bsr 6) + 16#C0);
utf8_encode_char(Char) when Char =< 16#7F ->
  encode_char(Char).

encode_char(Char) ->
  [hex_char(Char rem 16), hex_char(Char div 16), $%].

hex_char(C) when C < 10 -> $0 + C;
hex_char(C) when C < 16 -> $A + C - 10.

value_to_string(Integer) when is_integer(Integer) -> integer_to_list(Integer);
value_to_string(Atom) when is_atom(Atom) -> atom_to_list(Atom);
value_to_string(Binary) when is_binary(Binary) -> Binary;
value_to_string(String) when is_list(String) -> unicode:characters_to_binary(String).


get_timeout(#aws_config{timeout = undefined}) ->
  ?ERLCLOUD_RETRY_TIMEOUT;
get_timeout(#aws_config{timeout = Timeout}) ->
  Timeout.

