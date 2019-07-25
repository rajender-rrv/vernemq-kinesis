%%%-------------------------------------------------------------------
%%% @author user
%%% @copyright (C) 2019, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 22. Jul 2019 1:13 PM
%%%-------------------------------------------------------------------
-author("user").



-record(aws_config, {

  aws_region = undefined :: string()|undefined,
  access_key_id :: string()|undefined|false,
  secret_access_key :: string()|undefined|false,
  security_token = undefined :: string()|undefined,

  kinesis_scheme = "https://" :: string(),
  kinesis_host = "kinesis.ap-south-1.amazonaws.com" :: string(),
  kinesis_port = 80 :: non_neg_integer(),
  kinesis_retry = fun myplugin:retry/2 :: myplugin:retry_fun(),

  timeout = undefined :: timeout()|undefined,
  http_client = httpc :: myplugin_httpc:request_fun(),
  hackney_pool = default :: atom(),
  lhttpc_pool = undefined :: atom(),
  encode = true::string()

}).
-type(aws_config() :: #aws_config{}).

-type proplist() :: proplists:proplist().
