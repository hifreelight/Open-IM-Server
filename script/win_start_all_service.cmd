SET ROOT=%cd%
cd %ROOT%\..\bin\
start "1" cmd /C .\open_im_api.exe -port 10002
start "2" cmd /C .\open_im_cms_api.exe -port 10006
start "3" cmd /C .\open_im_user.exe -port 10110
start "4" cmd /C .\open_im_friend.exe -port 10120
start "5" cmd /C .\open_im_group.exe -port 10150
start "6" cmd /C .\open_im_auth.exe -port 10160
start "7" cmd /C .\open_im_admin_cms.exe -port 10200
start "8" cmd /C .\open_im_message_cms.exe -port 10190
start "9" cmd /C .\open_im_statistics.exe -port 10180
start "10" cmd /C .\open_im_msg.exe -port 10130
start "11" cmd /C .\open_im_office.exe -port 10210
start "12" cmd /C .\open_im_organization.exe -port 10220
start "13" cmd /C .\open_im_conversation.exe -port 10230
start "14" cmd /C .\open_im_cache.exe -port 10240
start "15" cmd /C .\open_im_push.exe -port 10170
start "16" cmd /C .\open_im_msg_transfer.exe
start "17" cmd /C .\open_im_sdk_server.exe -openIM_api_port 10002 -openIM_ws_port 10001 -sdk_ws_port 10003 -openIM_log_level 6
start "18" cmd /C .\open_im_msg_gateway.exe -rpc_port 10140 -ws_port 10001
start "19" cmd /C .\open_im_demo.exe -port 10004
cd %ROOT%