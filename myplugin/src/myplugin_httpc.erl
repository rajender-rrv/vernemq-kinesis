%% @author Ransom Richardson <ransom@ransomr.net>
%% @doc
%%
%% HTTP client abstraction for erlcloud. Simplifies changing http clients.
%% API matches lhttpc, except Config is passed instead of options for
%% future cusomizability.
%%
%% @end

-module(myplugin_httpc).

-include("myplugin.hrl").

-export([request/6]).

-type request_fun() ::
lhttpc | httpc | hackney |
{module(), atom()} |
fun((string(),
head | get | put | post | trace | options | delete,
list({binary(), binary()}),
binary(), pos_integer(), #aws_config{}) ->
  {ok, {{pos_integer(), string()},
    list({string(), string()}), binary()}} |
  {error, any()}).
-export_type([request_fun/0]).

request(URL, Method, Hdrs, Body, Timeout,
    #aws_config{http_client = lhttpc} = Config) ->
  request_lhttpc(URL, Method, Hdrs, Body, Timeout, Config);
request(URL, Method, Hdrs, Body, Timeout,
    #aws_config{http_client = httpc} = Config) ->
  request_httpc(URL, Method, Hdrs, Body, Timeout, Config);
request(URL, Method, Hdrs, Body, Timeout,
    #aws_config{http_client = hackney} = Config) ->
  request_hackney(URL, Method, Hdrs, Body, Timeout, Config);
request(URL, Method, Hdrs, Body, Timeout,
    #aws_config{http_client = {M, F}} = Config)
  when is_atom(M), is_atom(F) ->
  M:F(URL, Method, Hdrs, Body, Timeout, Config);
request(URL, Method, Hdrs, Body, Timeout,
    #aws_config{http_client = F} = Config)
  when is_function(F, 6) ->
  F(URL, Method, Hdrs, Body, Timeout, Config).

request_lhttpc(URL, Method, Hdrs, Body, Timeout, #aws_config{lhttpc_pool = undefined}) ->
  lhttpc:request(URL, Method, Hdrs, Body, Timeout, []);
request_lhttpc(URL, Method, Hdrs, Body, Timeout, #aws_config{lhttpc_pool = Pool}) ->
  LHttpcOpts = [{pool, Pool}, {pool_ensure, true}],
  lhttpc:request(URL, Method, Hdrs, Body, Timeout, LHttpcOpts).

%% Guard clause protects against empty bodied requests from being
%% unable to find a matching httpc:request call.
request_httpc(URL, Method, Hdrs, <<>>, Timeout, _Config)
  when (Method =:= options) orelse
  (Method =:= get) orelse
  (Method =:= head) orelse
  (Method =:= delete) orelse
  (Method =:= trace) ->
  HdrsStr = [{to_list_string(K), to_list_string(V)} || {K, V} <- Hdrs],
  response_httpc(httpc:request(Method, {URL, HdrsStr},
    [{timeout, Timeout}],
    [{body_format, binary}]));
request_httpc(URL, Method, Hdrs, Body, Timeout, _Config) ->
  HdrsStr = [{to_list_string(K), to_list_string(V)} || {K, V} <- Hdrs],
  {"content-type", ContentType} = lists:keyfind("content-type", 1, HdrsStr),
  response_httpc(httpc:request(Method,
    {URL, HdrsStr,
      ContentType, Body},
    [{timeout, Timeout}],
    [{body_format, binary}])).

request_hackney(URL, Method, Hdrs, Body, Timeout, #aws_config{hackney_pool = Pool}) ->
  BinURL = to_binary(URL),
  BinHdrs = [{to_binary(K), to_binary(V)} || {K, V} <- Hdrs],
  PoolOpt = if Pool =:= undefined ->
    [];
              true ->
                [{pool, Pool}]
            end,
  response_hackney(hackney:request(Method,
    BinURL, BinHdrs,
    Body,
    [{recv_timeout, Timeout}] ++ PoolOpt)).

response_httpc({ok, {{_HTTPVer, Status, StatusLine}, Headers, Body}}) ->
%%  lager:info("~n Status: ~w ~n StatusLine: ~w ~n Body: ~w ~n ~n", [Status, StatusLine, Body]),
%%  lager:info("~n Status: ~n StatusLine: ~n Body: ~n ~n", [Status, StatusLine, Body]),
  {ok, {{Status, StatusLine}, Headers, Body}};
response_httpc({error, _} = Error) ->
  Error.

response_hackney({ok, Status, Hdrs}) ->
  HdrsStr = header_str(Hdrs),
  {ok, {{Status, undefined}, HdrsStr, undefined}};
response_hackney({ok, Status, Hdrs, Ref}) ->
  case hackney:body(Ref) of
    {ok, Body} ->
      HdrsStr = header_str(Hdrs),
      {ok, {{Status, undefined}, HdrsStr, Body}};
    {error, Reason} when Status >= 200, Status =< 299 ->
      {error, {hackney_error, Reason}};
    {error, _} ->
      HdrsStr = header_str(Hdrs),
      {ok, {{Status, undefined}, HdrsStr, undefined}}
  end;
response_hackney({error, _} = Error) ->
  Error.

header_str(Hdrs) ->
  [{string:to_lower(to_list_string(K)), to_list_string(V)} || {K, V} <- Hdrs].

to_list_string(Val) when erlang:is_binary(Val) ->
  erlang:binary_to_list(Val);
to_list_string(Val) when erlang:is_list(Val) ->
  Val.

to_binary(Val) when erlang:is_list(Val) ->
  erlang:list_to_binary(Val);
to_binary(Val) when erlang:is_binary(Val) ->
  Val.

