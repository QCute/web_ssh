-module(web_ssh).
%% escript entry
-export([main/1]).
-export([do/1]).
%% supervisor and gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
%% ssl key callback
-export([is_host_key/4, user_key/2, add_host_key/3]).
-include_lib("inets/include/httpd.hrl").
-include_lib("ssl/src/ssl_api.hrl").
%% server state
-record(state, {socket, ref, channel_id = 0, data = <<>>}).
%%%===================================================================
%%% API
%%%===================================================================
main(Args) ->
    ArgList = lists:reverse(lists:foldl(fun([$-, $-], _) -> erlang:error("unknown option: --"); ([$-, $- | K], A) -> [Key | Value] = string:tokens("-" ++ K, "="), [{Key, Value} | A];(K = [$- | _], A) -> [{K, []} | A];(V, [{K, L} | T]) -> [{K, lists:reverse([V | lists:reverse(L)])} | T];(_, A) -> A end, [], Args)),
    [Port | _] = proplists:get_value("-port", ArgList, [""]),
    [Type | _] = proplists:get_value("-mode", ArgList, ["tcp"]),
    [Cert | _] = proplists:get_value("-ssl-cert", ArgList, [""]),
    [Key | _] = proplists:get_value("-ssl-key", ArgList, [""]),
    Options = proplists:get_value(Type, [{"ssl", [{socket_type, {ssl, [{certfile, Cert}, {keyfile, Key}]}}]}], []),
    (Port =/= [] andalso Type =/= [] andalso start(list_to_integer(Port), Options) == ok) orelse help().

help() ->
    io:format("
USAGE:
    run [OPTIONS]

FLAGS:
    -help                                          Prints help information

OPTIONS:
    -ssl-cert <ssl-cert>                           SSL Cert File Path
    -ssl-key <ssl-key>                             SSL Key File Path
    -mode <mode>                                   HTTP mode tcp or ssl
    -port <port>                                   Port
").

%%%===================================================================
%%% HTTP Server
%%%===================================================================
%% http server
start(Port, Options) ->
    ssh:start(),
    ssl:start(),
    inets:start(),
    httpd:start_service(lists:merge(Options, [{ipfamily, inet}, {port, Port}, {server_name, ""}, {server_root, "."}, {document_root, "."}, {modules, [?MODULE]}])),
    timer:sleep(infinity).

do(#mod{socket = Socket, parsed_header = ParsedHeader}) ->
    ProtocolList = [Protocol | _] = [string:strip(Protocol) || Protocol <- string:tokens(proplists:get_value("sec-websocket-protocol", ParsedHeader, ""), ",")],
    handshake(Socket, ParsedHeader, Protocol),
    set_opts(Socket),
    gen_server:cast(self(), {start, ProtocolList}),
    gen_server:enter_loop(?MODULE, [], #state{socket = Socket}).

%%%===================================================================
%%% gen_server Callback
%%%===================================================================
init(Args) ->
    {ok, Args}.

handle_call(_Info, _From, State) ->
    {reply, ok, State}.

handle_cast({start, ProtocolList}, State) ->
    connect(State, ProtocolList);
handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({Type, Socket, Binary}, State = #state{socket = Socket, data = Data}) when Type == tcp orelse Type == ssl ->
    %% ssh execute
    decode_web_socket_packet(<<Data/binary, Binary/binary>>, State#state{data = <<>>});
handle_info({ssh_cm, Ref, {data, ChannelId, _, Binary}}, State = #state{socket = Socket, ref = Ref, channel_id = ChannelId}) ->
    ssh_connection:adjust_window(Ref, ChannelId, byte_size(Binary)),
    %% ssh data
    send_web_socket(Socket, Binary),
    {noreply, State};
handle_info({ssh_cm, Ref, {eof, ChannelId}}, State = #state{ref = Ref, channel_id = ChannelId}) ->
    %% ssh reply
    {noreply, State};
handle_info({ssh_cm, Ref, {closed, ChannelId}}, State = #state{ref = Ref, channel_id = ChannelId}) ->
    %% ssh reply
    {stop, {shutdown, <<>>}, State};
handle_info({ssh_cm, Ref, {exit_status, ChannelId, 0}}, State = #state{ref = Ref, channel_id = ChannelId}) ->
    %% ssh reply
    {stop, {shutdown, <<>>}, State};
handle_info({ssh_cm, Ref, {exit_status, ChannelId, Status}}, State = #state{ref = Ref, channel_id = ChannelId}) ->
    %% ssh reply
    {stop, {shutdown, <<"Connection closed by peer: ", (integer_to_binary(Status))/binary>>}, State};
handle_info({ssh_cm, Ref, {exit_signal, ChannelId, _, Error, _}}, State = #state{ref = Ref, channel_id = ChannelId}) ->
    %% ssh reply
    {stop, {shutdown, <<"Connection closed by peer: ", (iolist_to_binary(Error))/binary>>}, State};
handle_info({tcp_closed, Socket}, State = #state{socket = Socket}) ->
    {stop, normal, State};
handle_info({ssl_closed, Socket}, State = #state{socket = Socket}) ->
    {stop, normal, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate({shutdown, Reason}, State = #state{socket = Socket}) ->
    send_web_socket(Socket, Reason),
    send_web_socket_close(Socket),
    terminate(normal, State);
terminate(_Reason, State = #state{socket = Socket, ref = Ref}) ->
    ssh:close(Ref),
    close(Socket),
    {ok, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
%%%===================================================================
%%% Transport Control
%%%===================================================================
%% set active
set_opts(Socket = #sslsocket{}) ->
    ssl:setopts(Socket, [{active, true}]);
set_opts(Socket) ->
    inet:setopts(Socket, [{active, true}]).

%% send
send(Socket = #sslsocket{}, Binary) ->
    ssl:send(Socket, Binary);
send(Socket, Binary) ->
    gen_tcp:send(Socket, Binary).

%% close
close(Socket = #sslsocket{}) ->
    ssl:close(Socket);
close(Socket) ->
    gen_tcp:close(Socket).

%%%===================================================================
%%% SSH Proxy
%%%===================================================================
%% connect to ssh server
connect(State, [Host, Port, User, "password", Password | _]) when Host =/= <<>> andalso Port =/= <<>> andalso User =/= <<>> andalso Password =/= <<>> ->
    start_shell(State, Host, Port, [{user, http_uri:decode(User)}, {password, http_uri:decode(Password)}, {auth_methods, "password"}]);
connect(State, [Host, Port, User, "key", Key, Password | _]) when Host =/= <<>> andalso Port =/= <<>> andalso User =/= <<>> andalso Key =/= <<>> andalso Password =/= <<>> ->
    start_shell(State, Host, Port, [{user, http_uri:decode(User)}, {rsa_pass_phrase, http_uri:decode(Password)}, {auth_methods, "publickey"}, {key_cb, {?MODULE, [{private_key, base64:decode(Key)}]}}]);
connect(State, [Host, Port, User, "key", Key | _]) when Host =/= <<>> andalso Port =/= <<>> andalso User =/= <<>> andalso Key =/= <<>> ->
    start_shell(State, Host, Port, [{user, http_uri:decode(User)}, {auth_methods, "publickey"}, {key_cb, {?MODULE, [{private_key, http_uri:decode(Key)}]}}]);
connect(State, Protocol) ->
    {stop, {shutdown, <<"error connect parameter: ", (list_to_binary(string:join(Protocol, ",")))/binary>>}, State}.

start_shell(State, Host, Port, Options) ->
    case ssh:connect(Host, list_to_integer(Port), lists:merge(Options, [{silently_accept_hosts, true}, {save_accepted_host, false}, {disconnectfun, fun(_) -> ok end}])) of
        {ok, Ref} ->
            case ssh_connection:session_channel(Ref, infinity) of
                {ok, ChannelId} ->
                    success = ssh_connection:ptty_alloc(Ref, ChannelId, []),
                    ok = ssh_connection:shell(Ref, ChannelId),
                    {noreply, State#state{ref = Ref, channel_id = ChannelId}};
                _ ->
                    {stop, {shutdown, <<"could not start session channel: closed">>}, State}
            end;
        {error, Reason} ->
            {stop, {shutdown, iolist_to_binary(Reason)}, State}
    end.

%% ssh_client_key_api callback
user_key('ssh-rsa', Options) ->
    Pem = proplists:get_value(private_key, proplists:get_value(key_cb_private, Options)),
    Password = proplists:get_value(rsa_pass_phrase, Options, []),
    case public_key:pem_decode(iolist_to_binary(Pem)) of
        [{_, _, not_encrypted} = Entry]  ->
            {ok, public_key:pem_entry_decode(Entry)};
        [Entry] when Password =/= [] ->
            {ok, public_key:pem_entry_decode(Entry, Password)};
        _ ->
            throw("No pass phrase provided for private key file")
    end;
user_key(Algorithm, _) ->
    {error, Algorithm}.

%% ssh_client_key_api callback
is_host_key(Key, Host, Algorithm, Options) ->
    ssh_file:is_host_key(Key, Host, Algorithm, Options).

%% ssh_client_key_api callback
add_host_key(Host, PublicKey, Options) ->
    ssh_file:add_host_key(Host, PublicKey, Options).

%% handle msg
handle_msg(Command, State = #state{ref = Ref, channel_id = ChannelId}) ->
    ssh_connection:send(Ref, ChannelId, Command),
    {noreply, State}.
%%%===================================================================
%%% WebSocket
%%%===================================================================
%% web socket handshake
handshake(Socket, Fields, Protocol) ->
    Upgrade = proplists:get_value("upgrade", Fields, ""),
    SecKey = proplists:get_value("sec-websocket-key", Fields, ""),
    Hash = crypto:hash(sha, <<(list_to_binary(SecKey))/binary, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11">>),
    Encode = base64:encode_to_string(Hash),
    Binary = [<<"HTTP/1.1 101 Switching Protocols\r\n">>, <<"Upgrade: ">>, Upgrade, <<"\r\n">>, <<"Connection: Upgrade\r\n">>, <<"Sec-WebSocket-Accept: ">>, Encode, <<"\r\n">>, <<"Sec-WebSocket-Protocol: ">>, Protocol, <<"\r\n">>, <<"\r\n">>],
    send(Socket, list_to_binary(Binary)).

%% decode web socket packet
decode_web_socket_packet(<<_:4, 8:4, Mask:1, Length:7, _:Mask/binary-unit:32, _:Length/binary, _/binary>>, State) ->
    %% quick close/client close active
    {stop, normal, State};
decode_web_socket_packet(<<_:8, Mask:1, 127:7, Length:64, Masking:Mask/binary-unit:32, Body:Length/binary, Rest/binary>>, State) ->
    Payload = unmask(Body, Masking, <<>>),
    handle_msg(Payload, State#state{data = Rest});
decode_web_socket_packet(<<_:8, Mask:1, 126:7, Length:64, Masking:Mask/binary-unit:32, Body:Length/binary, Rest/binary>>, State) ->
    Payload = unmask(Body, Masking, <<>>),
    handle_msg(Payload, State#state{data = Rest});
decode_web_socket_packet(<<_:8, Mask:1, Length:7, Masking:Mask/binary-unit:32, Body:Length/binary, Rest/binary>>, State) ->
    Payload = unmask(Body, Masking, <<>>),
    handle_msg(Payload, State#state{data = Rest});
decode_web_socket_packet(Data, State) ->
    {noreply, State#state{data = Data}}.

%% unmask (Draft-HiXie-76)
unmask(<<>>, _Masking, Acc) ->
    Acc;
unmask(PayLoad, <<>>, _) ->
    PayLoad;
unmask(<<Payload:8>>, <<Mask:8, _/binary>>, Acc) ->
    <<Acc/binary, (Payload bxor Mask):8>>;
unmask(<<Payload:16>>, <<Mask:16, _/binary>>, Acc) ->
    <<Acc/binary, (Payload bxor Mask):16>>;
unmask(<<Payload:24>>, <<Mask:24, _/binary>>, Acc) ->
    <<Acc/binary, (Payload bxor Mask):24>>;
unmask(<<Payload:32, Rest/binary>>, Masking = <<Mask:32, _/binary>>, Acc) ->
    unmask(Rest, Masking, <<Acc/binary, (Payload bxor Mask):32>>).

%% send web socket packet
send_web_socket(Socket, Binary) when byte_size(Binary) =< 125 ->
    send(Socket, <<1:1, 0:3, 2:4, 0:1, (byte_size(Binary)):7, Binary/binary>>);
send_web_socket(Socket, Binary) when byte_size(Binary) =< 16#FFFF ->
    send(Socket, <<1:1, 0:3, 2:4, 0:1, 126:7, (byte_size(Binary)):16, Binary/binary>>);
send_web_socket(Socket, Binary) ->
    send(Socket, <<1:1, 0:3, 2:4, 0:1, 127:7, (byte_size(Binary)):64, Binary/binary>>).

%% send web socket close
send_web_socket_close(Socket) ->
    send(Socket, <<1:1, 0:3, 8:4, 0:1, 0:7>>).

%%%===================================================================
%%% End
%%%===================================================================
