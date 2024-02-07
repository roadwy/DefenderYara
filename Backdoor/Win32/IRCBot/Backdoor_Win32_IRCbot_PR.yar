
rule Backdoor_Win32_IRCbot_PR{
	meta:
		description = "Backdoor:Win32/IRCbot.PR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 50 00 79 00 54 00 68 00 30 00 6e 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 50 00 79 00 54 00 68 00 30 00 6e 00 20 00 42 00 6f 00 74 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  \PyTh0n\Desktop\PyTh0n Bot\Project1.vbp
		$a_01_1 = {53 6f 63 6b 65 74 49 52 43 5f 44 61 74 61 41 72 72 69 76 61 6c } //01 00  SocketIRC_DataArrival
		$a_00_2 = {69 00 72 00 63 00 2e 00 63 00 79 00 62 00 65 00 72 00 61 00 72 00 6d 00 79 00 2e 00 6e 00 65 00 74 00 } //01 00  irc.cyberarmy.net
		$a_01_3 = {25 53 6f 63 6b 65 74 49 52 43 } //01 00  %SocketIRC
		$a_01_4 = {52 65 6d 6f 74 65 50 6f 72 74 } //01 00  RemotePort
		$a_01_5 = {52 65 6d 6f 74 65 48 6f 73 74 } //01 00  RemoteHost
		$a_01_6 = {53 74 61 72 74 42 6f 74 } //01 00  StartBot
		$a_01_7 = {44 6f 53 5f 43 6f 6e 6e 65 63 74 } //00 00  DoS_Connect
	condition:
		any of ($a_*)
 
}