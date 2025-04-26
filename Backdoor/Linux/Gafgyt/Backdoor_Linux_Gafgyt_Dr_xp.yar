
rule Backdoor_Linux_Gafgyt_Dr_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.Dr!xp,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {75 64 70 66 6c 6f 6f 64 } //1 udpflood
		$a_00_1 = {61 63 6b 66 6c 6f 6f 64 } //1 ackflood
		$a_00_2 = {73 74 64 66 6c 6f 6f 64 } //1 stdflood
		$a_00_3 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 65 73 74 61 62 6c 69 73 68 65 64 20 74 6f 20 63 6e 63 } //1 connection established to cnc
		$a_00_4 = {4b 69 6c 6c 65 64 20 25 64 20 50 49 44 73 } //1 Killed %d PIDs
		$a_00_5 = {62 6f 74 5f 68 6f 73 74 } //1 bot_host
		$a_00_6 = {73 74 64 5f 73 65 6e 64 } //1 std_send
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}