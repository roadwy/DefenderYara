
rule Backdoor_Linux_Luabot_A{
	meta:
		description = "Backdoor:Linux/Luabot.A,SIGNATURE_TYPE_ELFHSTR_EXT,0e 00 0e 00 14 00 00 01 00 "
		
	strings :
		$a_00_0 = {6c 75 61 5f 65 76 73 6f 63 6b 65 74 5f 73 65 72 76 65 72 5f 61 63 63 65 70 74 5f 63 62 } //01 00  lua_evsocket_server_accept_cb
		$a_00_1 = {6c 75 61 5f 65 76 73 69 67 6e 61 6c 5f 6e 65 77 } //01 00  lua_evsignal_new
		$a_00_2 = {6c 75 61 66 5f 65 76 73 6f 63 6b 65 74 5f 73 65 76 65 72 5f 6e 65 77 } //01 00  luaf_evsocket_sever_new
		$a_00_3 = {62 6f 74 5f 64 61 65 6d 6f 6e 69 7a 65 } //01 00  bot_daemonize
		$a_00_4 = {63 68 65 63 6b 61 6e 75 73 5f 73 75 63 75 72 61 6e 75 73 2e 6c 75 61 } //01 00  checkanus_sucuranus.lua
		$a_00_5 = {31 30 75 74 69 6c 73 2e 6c 75 61 } //01 00  10utils.lua
		$a_00_6 = {31 31 64 75 6d 70 65 72 2e 6c 75 61 } //01 00  11dumper.lua
		$a_00_7 = {32 30 72 65 2e 6c 75 61 } //01 00  20re.lua
		$a_00_8 = {32 35 6c 69 73 74 2e 6c 75 61 } //01 00  25list.lua
		$a_00_9 = {33 30 63 6f 63 6f 72 6f 2e 6c 75 61 } //01 00  30cocoro.lua
		$a_00_10 = {33 35 70 72 6f 63 75 74 69 6c 73 2e 6c 75 61 } //01 00  35procutils.lua
		$a_00_11 = {34 30 6c 70 65 67 72 2e 6c 75 61 } //01 00  40lpegr.lua
		$a_00_12 = {35 30 6c 70 65 67 70 2e 6c 75 61 } //01 00  50lpegp.lua
		$a_00_13 = {37 30 72 65 73 6f 6c 76 65 72 2e 6c 75 61 } //01 00  70resolver.lua
		$a_00_14 = {38 30 65 76 75 74 69 6c 73 2e 6c 75 61 } //01 00  80evutils.lua
		$a_00_15 = {38 31 62 73 6f 63 6b 65 74 2e 6c 75 61 } //01 00  81bsocket.lua
		$a_00_16 = {38 32 65 76 73 65 72 76 65 72 2e 6c 75 61 } //01 00  82evserver.lua
		$a_00_17 = {38 35 6b 69 6c 6c 6f 6c 64 2e 6c 75 61 } //01 00  85killold.lua
		$a_00_18 = {65 76 73 65 72 76 65 72 2e 6c 75 61 } //01 00  evserver.lua
		$a_00_19 = {6c 75 61 5f 73 63 72 69 70 74 5f 72 75 6e 6e 65 72 2e 6c 75 61 } //00 00  lua_script_runner.lua
		$a_00_20 = {5d 04 00 } //00 c0 
	condition:
		any of ($a_*)
 
}