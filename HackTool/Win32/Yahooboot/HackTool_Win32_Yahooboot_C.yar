
rule HackTool_Win32_Yahooboot_C{
	meta:
		description = "HackTool:Win32/Yahooboot.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {59 00 61 00 68 00 6f 00 6f 00 20 00 52 00 6f 00 6f 00 6d 00 20 00 42 00 6f 00 6f 00 74 00 65 00 72 00 } //03 00  Yahoo Room Booter
		$a_01_1 = {59 00 6f 00 75 00 20 00 6d 00 75 00 73 00 74 00 20 00 6c 00 6f 00 61 00 64 00 20 00 79 00 6f 00 75 00 72 00 20 00 62 00 6f 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 6c 00 6f 00 67 00 69 00 6e 00 20 00 21 00 21 00 21 00 } //02 00  You must load your bots and login !!!
		$a_01_2 = {4d 6f 64 52 6f 6f 6d 50 63 6b 73 } //00 00  ModRoomPcks
	condition:
		any of ($a_*)
 
}