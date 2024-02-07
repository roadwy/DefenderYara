
rule Backdoor_Linux_Mirai_I_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.I!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 6b 5f 75 64 70 5f 73 69 6d 70 6c 65 } //01 00  attack_udp_simple
		$a_00_1 = {61 74 74 61 63 6b 5f 75 64 70 6d 6f 70 } //01 00  attack_udpmop
		$a_00_2 = {6b 69 6c 6c 5f 61 74 74 61 63 6b 73 } //01 00  kill_attacks
		$a_00_3 = {63 6d 64 5f 6e 6f 74 5f 61 74 74 61 63 6b } //01 00  cmd_not_attack
		$a_00_4 = {6b 69 6c 6c 65 72 5f 72 75 6e } //00 00  killer_run
	condition:
		any of ($a_*)
 
}