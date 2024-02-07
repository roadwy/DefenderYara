
rule Backdoor_Linux_Gafgyt_AG_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AG!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6f 72 5f 61 64 64 5f 73 6f 63 6b } //01 00  tor_add_sock
		$a_01_1 = {74 63 70 72 61 77 } //01 00  tcpraw
		$a_01_2 = {75 64 70 70 6c 61 69 6e } //01 00  udpplain
		$a_01_3 = {6d 61 69 6e 5f 69 6e 73 74 61 6e 63 65 5f 6b 69 6c 6c } //00 00  main_instance_kill
		$a_00_4 = {5d 04 00 } //00 a1 
	condition:
		any of ($a_*)
 
}