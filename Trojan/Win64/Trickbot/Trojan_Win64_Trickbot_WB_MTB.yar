
rule Trojan_Win64_Trickbot_WB_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.WB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_80_0 = {73 6f 63 6b 73 62 6f 74 2e 64 6c 6c } //socksbot.dll  01 00 
		$a_80_1 = {66 69 6c 65 20 3d 20 22 62 63 63 6f 6e 66 69 67 } //file = "bcconfig  01 00 
		$a_80_2 = {43 61 6e 27 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 73 65 72 76 65 72 } //Can't connect to server  01 00 
		$a_80_3 = {43 61 6e 27 74 20 63 72 65 61 74 65 20 69 6f 5f 73 65 72 76 69 63 65 } //Can't create io_service  01 00 
		$a_80_4 = {57 53 41 52 65 63 76 20 74 69 6d 65 20 6f 75 74 } //WSARecv time out  01 00 
		$a_80_5 = {44 69 73 63 6f 6e 6e 65 63 74 69 6e 67 } //Disconnecting  01 00 
		$a_80_6 = {49 6e 76 61 6c 69 64 20 70 61 72 65 6e 74 49 44 } //Invalid parentID  00 00 
	condition:
		any of ($a_*)
 
}