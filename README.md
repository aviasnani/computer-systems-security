Picking up task  WebSocket | Socket.IO  integration in client side 
User Story### I want to send messages that appear instantly to all peep's
+whenn user clicks on send message then client will emit to websocket server and from there server will broadcaast to all connected clients and when client receives then it should appear on scren and if this process fails for some reason to send msg then should indicate an error and throw some message on console where did the error occured . 
-- Make it work then will add encrypt over it 

Message Flow
User types balh balh --> emit to server --> server broadcasts --> all clients receive --> update UI 


Front end --> chat --> socket io client -- > Message handle [in and out ]--> UI state handling
Backend --> socket io server -- > Message Router --> Room Manager --> Database  --> SQLite 


https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_client_applications
https://github.com/websockets/ws?tab=readme-ov-file#sending-and-receiving-text-data

Frontend - connect disconnect joinRoom leaveRoom sendMessage onMessage onConnectionStatus
Backend - handle_connect handle_disconnect  handle_join_room handle_leave_room handle_message  +++ add_user_to_room remove_user_from_room  get_room_users  broadcast_to_room
data - room model 
handle errors - network error auth error server down message fail basic check input msg 


--> next phase --> make sure that only authenticated clients should send the message 
