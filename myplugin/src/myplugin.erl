%%%-------------------------------------------------------------------
%%% @author user
%%% @copyright (C) 2019, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 16. Jul 2019 11:50 AM
%%%-------------------------------------------------------------------
-module(myplugin).
-author("user").
-behaviour(auth_on_register_hook).
-behaviour(auth_on_subscribe_hook).
-behaviour(auth_on_publish_hook).
-behaviour(on_publish_hook).
-include("myplugin.hrl").

-define(NUM_ATTEMPTS, 10).

-export([auth_on_register/5, auth_on_publish/6, auth_on_subscribe/3, on_publish/6,
  hi/0, rest_get/0, rest_post/0, put_record/0, put_record/6, retry/2]).

-type attempt() :: {attempt, pos_integer()} | {error, term()}.
-type retry_fun() :: fun((pos_integer(), term()) -> attempt()).

backoff(1) -> ok;
backoff(Attempt) ->
  timer:sleep(erlcloud_util:rand_uniform((1 bsl (Attempt - 1)) * 100)).

retry(Attempt, Reason) when Attempt >= ?NUM_ATTEMPTS ->
  {error, Reason};
retry(Attempt, _) ->
  backoff(Attempt),
  {attempt, Attempt + 1}.


%%default_config() ->
%%  case get(aws_config) of
%%    undefined -> default_config_wrap();
%%    Config -> Config
%%  end.

%% This file demonstrates the hooks you typically want to use
%% if your plugin deals with Authentication or Authorization.
%%
%% All it does is:
%%  - authenticate every user and write the log
%%  - authorize every PUBLISH and SUBSCRIBE and write it to the log
%%
%% You don't need to implement all of these hooks, just the one
%% needed for your use case.
%%
%% IMPORTANT:
%%  these hook functions run in the session context
%%
auth_on_register({_IpAddr, _Port} = Peer, {_MountPoint, _ClientId} = SubscriberId, UserName, Password, CleanSession) ->
  lager:info("auth_on_register: ~p ~p ~p ~p ~p", [Peer, SubscriberId, UserName, Password, CleanSession]),
  io:fwrite("auth_on_register: ~p ~p ~p ~p ~p", [Peer, SubscriberId, UserName, Password, CleanSession]),
  %% do whatever you like with the params, all that matters
  %% is the return value of this function
  %%
  %% 1. return 'ok' -> CONNECT is authenticated
  %% 2. return 'next' -> leave it to other plugins to decide
  %% 3. return {ok, [{ModifierKey, NewVal}...]} -> CONNECT is authenticated, but we might want to set some options used throughout the client session:
  %%      - {mountpoint, NewMountPoint::string}
  %%      - {clean_session, NewCleanSession::boolean}
  %% 4. return {error, invalid_credentials} -> CONNACK_CREDENTIALS is sent
  %% 5. return {error, whatever} -> CONNACK_AUTH is sent

  %% we return 'ok'
  ok.

auth_on_publish(UserName, {_MountPoint, _ClientId} = SubscriberId, QoS, Topic, Payload, IsRetain) ->
  lager:info("auth_on_publish: ~p ~p ~p ~p ~p ~p", [UserName, SubscriberId, QoS, Topic, Payload, IsRetain]),
  io:fwrite("auth_on_publish: ~p ~p ~p ~p ~p ~p", [UserName, SubscriberId, QoS, Topic, Payload, IsRetain]),
  %% do whatever you like with the params, all that matters
  %% is the return value of this function
  %%
  %% 1. return 'ok' -> PUBLISH is authorized
  %% 2. return 'next' -> leave it to other plugins to decide
  %% 3. return {ok, NewPayload::binary} -> PUBLISH is authorized, but we changed the payload
  %% 4. return {ok, [{ModifierKey, NewVal}...]} -> PUBLISH is authorized, but we might have changed different Publish Options:
  %%     - {topic, NewTopic::string}
  %%     - {payload, NewPayload::binary}
  %%     - {qos, NewQoS::0..2}
  %%     - {retain, NewRetainFlag::boolean}
  %% 5. return {error, whatever} -> auth chain is stopped, and message is silently dropped (unless it is a Last Will message)
  %%
  %% we return 'ok'
  ok.

auth_on_subscribe(UserName, ClientId, [{_Topic, _QoS} | _] = Topics) ->
  lager:info("auth_on_subscribe: ~p ~p ~p", [UserName, ClientId, Topics]),
  io:fwrite("auth_on_subscribe: ~p ~p ~p", [UserName, ClientId, Topics]),
  %% do whatever you like with the params, all that matters
  %% is the return value of this function
  %%
  %% 1. return 'ok' -> SUBSCRIBE is authorized
  %% 2. return 'next' -> leave it to other plugins to decide
  %% 3. return {error, whatever} -> auth chain is stopped, and no SUBACK is sent

  %% we return 'ok'
  ok.

on_publish(UserName, {_MountPoint, _ClientId} = SubscriberId, QoS, Topic, Payload, IsRetain) ->
  io:fwrite("UserName ~w SubscriberId ~w QoS ~w Topic ~w Payload ~w IsRetain ~w ~n ~n", [UserName, SubscriberId, QoS, Topic, Payload, IsRetain]),
  lager:info("UserName ~w SubscriberId ~w QoS ~w Topic ~w Payload ~w IsRetain ~w ~n ~n", [UserName, SubscriberId, QoS, Topic, Payload, IsRetain]),
%%  put_record(UserName, Topic, Payload, QoS),
%%  put_record(),
  ok.



hi() ->
  io:fwrite("Hi from io module ~n ~n"),
  lager:info("Hi from Lager module ~n ~n"),
  ok.

rest_get() ->
  inets:start(),
  Response = httpc:request(get, {"http://dummy.restapiexample.com/api/v1/employee/", []}, [], []),
%%  Body = response_body(Response),
  StatusCode = element(2, element(1, element(2, Response))),
  Status = element(3, element(1, element(2, Response))),
  lager:info("~n ~n StatusCode : ~w ~n ~n Status : ~w ~n ~n", [StatusCode, Status]),
  inets:stop(),
  init:stop().

rest_post() ->
  inets:start(),
  Method = post,
  Body = "{\"name\":\"vmq-1\",\"salary\":\"221317\",\"age\":\"22\"}",
  PostUrl = "http://dummy.restapiexample.com/api/v1/create",
  ContentType = "application/json",
  Header = [],
  Response = httpc:request(Method, {PostUrl, ContentType, Header, Body}, [], []),
  StatusCode = element(2, element(1, element(2, Response))),
  Status = element(3, element(1, element(2, Response))),
  lager:info("~n ~n StatusCode : ~w ~n ~n Status : ~w ~n ~n", [StatusCode, Status]),
  inets:stop(),
  init:stop().


put_record() ->
  StreamName = <<"vmqk5s">>,
  PartitionKey = <<"1">>,
  Data = <<"{\"deviceId\":\"53688900068704258\",\"UserId\":\"UserId-01230\",\"mqttTopic\":\"status\",\"qos\":\"1\",\"ts\":\"time stamp in utc\",\"payload\":\"on\"}">>,
  ExplicitHashKey = undefined,
  Ordering = undefined,
  Config = config(),
  Response = put_record(StreamName, PartitionKey, Data, ExplicitHashKey, Ordering, Config),
  lager:info("Response: ~n", [Response]).


put_record(StreamName, PartitionKey, Data, ExplicitHashKey, Ordering, Config) when is_record(Config, aws_config) ->
  Encoded = case Config#aws_config.encode of
              true -> base64:encode(Data);
              false -> Data
            end,
  Optional = [{<<"ExplicitHashKey">>, ExplicitHashKey},
    {<<"SequenceNumberForOrdering">>, Ordering}],
  Json = [{<<"StreamName">>, StreamName},
    {<<"PartitionKey">>, PartitionKey},
    {<<"Data">>, Encoded}
    | [KV || {_, V} = KV <- Optional, V /= undefined]],
  request(Config, "Kinesis_20131202.PutRecord", Json, true).

request(Config0, Operation, Json, ShouldDecode) ->
  Body = case Json of
           [] -> <<"{}">>;
           _ -> jsx:encode(Json)
         end,

  case utils:update_config(Config0) of
    {ok, Config} ->
      Headers = utils:headers(Config, Operation, Body),
      request_and_retry(Config, Headers, Body, ShouldDecode, {attempt, 1});
    {error, Reason} ->
      {error, Reason}
  end.

request_and_retry(_, _, _, _, {error, Reason}) ->
  {error, Reason};
request_and_retry(Config, Headers, Body, ShouldDecode, {attempt, Attempt}) ->
  RetryFun = Config#aws_config.kinesis_retry,
  case myplugin_httpc:request(
    url(Config), post,
    [{<<"content-type">>, <<"application/x-amz-json-1.1">>} | Headers],
    Body, utils:get_timeout(Config), Config) of

    {ok, {{200, _}, _, RespBody}} ->
      Result = case ShouldDecode of
                 true -> decode(RespBody);
                 false -> RespBody
               end,
      {ok, Result};

    {ok, {{Status, StatusLine}, _, RespBody}} when Status >= 400 andalso Status < 500 ->
      case client_error(Status, StatusLine, RespBody) of
        {retry, Reason} ->
          request_and_retry(Config, Headers, Body, ShouldDecode, RetryFun(Attempt, Reason));
        {error, Reason} ->
          {error, Reason}
      end;

    {ok, {{Status, StatusLine}, _, RespBody}} when Status >= 500 ->
      request_and_retry(Config, Headers, Body, ShouldDecode, RetryFun(Attempt, {http_error, Status, StatusLine, RespBody}));

    {ok, {{Status, StatusLine}, _, RespBody}} ->
      {error, {http_error, Status, StatusLine, RespBody}};

    {error, Reason} ->
      request_and_retry(Config, Headers, Body, ShouldDecode, RetryFun(Attempt, Reason))
  end.

client_error(Status, StatusLine, Body) ->
  try jsx:decode(Body) of
    Json ->
      Message = proplists:get_value(<<"message">>, Json, <<>>),
      case proplists:get_value(<<"__type">>, Json) of
        undefined ->
          {error, {http_error, Status, StatusLine, Body}};
        <<"ProvisionedThroughputExceededException">> = Type ->
          {retry, {Type, Message}};
        <<"ThrottlingException">> = Type ->
          {retry, {Type, Message}};
        <<"LimitExceededException">> = Type ->
          {retry, {Type, Message}};
        Other ->
          {error, {Other, Message}}
      end
  catch
    error:badarg ->
      {error, {http_error, Status, StatusLine, Body}}
  end.



url(#aws_config{kinesis_scheme = Scheme, kinesis_host = Host} = Config) ->
  lists:flatten([Scheme, Host, port_spec(Config)]).

port_spec(#aws_config{kinesis_port = 80}) ->
  "";
port_spec(#aws_config{kinesis_port = Port}) ->
  [":", erlang:integer_to_list(Port)].

decode(<<>>) -> [];
decode(JSON) -> jsx:decode(JSON).

config() ->
  #aws_config{
    aws_region = "ap-south-1",
    access_key_id = "AKIAUUMW54W2DFDX62KC",
    secret_access_key = "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",
    kinesis_scheme = "https://",
    kinesis_host = "kinesis.ap-south-1.amazonaws.com",
    kinesis_port = 80
  }.

%%erlcloud_put_record() ->
%%  application:ensure_all_started(erlcloud),
%%  application:set_env(erlcloud, aws_access_key_id, "AKIAUUMW54W2DFDX62KC"),
%%  application:set_env(erlcloud, aws_secret_access_key, "AS/fm7jwQzPe/k5nBe8MR3+mbJU/dI2qaTMLWwrC"),
%%  application:set_env(erlcloud, aws_region, "ap-south-1"),
%%  application:set_env(erlcloud, aws_security_token, "your token"),
%%  StreamName = <<"vmqk5s">>,
%%  PartitionKey = <<"1">>,
%%  Data = <<"{\"library\": \"jsx\", \"awesome\": true}">>,
%%  R = erlcloud_kinesis:put_record(StreamName, PartitionKey, Data),
%%  lager:info("R: ", [R]).


%%  Json = [{<<"deviceId">>, <<"dev-1001">>},
%%    {<<"userId">>, <<"u-2001">>},
%%    {<<"mqttTopic">>, <<"status">>},
%%    {<<"ts">>, <<"time in utc">>},
%%    {<<"payload">>, <<"payload">>}],
%%  Data = Json,


%%put_record(UserName, Topic, Payload, QoS) ->
%%  Json = [{<<"UserName">>, UserName},
%%    {<<"Topic">>, Topic},
%%    {<<"Payload">>, Payload},
%%    {<<"Qos">>, QoS}],
