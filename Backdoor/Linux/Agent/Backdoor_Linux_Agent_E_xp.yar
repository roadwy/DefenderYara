
rule Backdoor_Linux_Agent_E_xp{
	meta:
		description = "Backdoor:Linux/Agent.E!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 69 63 6d 70 2e 63 } //01 00  sendicmp.c
		$a_01_1 = {6f 70 65 6e 63 61 6c 6c 2e 63 } //01 00  opencall.c
		$a_01_2 = {69 63 6d 70 5f 73 69 64 } //01 00  icmp_sid
		$a_01_3 = {69 63 6d 70 2d 62 61 63 6b 64 6f 6f 72 20 25 73 2c 20 73 74 61 72 74 69 6e 67 20 73 65 72 76 65 72 2e 2e 2e } //00 00  icmp-backdoor %s, starting server...
		$a_00_4 = {5d 04 00 00 } //a9 12 
	condition:
		any of ($a_*)
 
}