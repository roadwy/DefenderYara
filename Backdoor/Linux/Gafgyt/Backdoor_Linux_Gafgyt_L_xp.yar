
rule Backdoor_Linux_Gafgyt_L_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.L!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 6b 5f 70 61 72 73 69 6e 67 } //1 attack_parsing
		$a_00_1 = {73 63 61 6e 6e 65 72 5f 6b 69 6c 6c } //1 scanner_kill
		$a_00_2 = {6b 69 6c 6c 65 72 5f 6b 69 6c 6c 5f 62 79 5f 63 6d 64 6c 69 6e 65 } //1 killer_kill_by_cmdline
		$a_00_3 = {74 63 70 62 79 70 61 73 73 } //1 tcpbypass
		$a_00_4 = {75 64 70 62 79 70 61 73 73 } //1 udpbypass
		$a_00_5 = {73 63 61 6e 6e 65 72 5f 70 61 75 73 65 5f 70 72 6f 63 65 73 73 } //1 scanner_pause_process
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}