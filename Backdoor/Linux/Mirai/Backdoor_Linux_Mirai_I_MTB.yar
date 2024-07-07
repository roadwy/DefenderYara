
rule Backdoor_Linux_Mirai_I_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.I!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 6b 5f 75 64 70 5f 73 69 6d 70 6c 65 } //1 attack_udp_simple
		$a_00_1 = {61 74 74 61 63 6b 5f 75 64 70 6d 6f 70 } //1 attack_udpmop
		$a_00_2 = {6b 69 6c 6c 5f 61 74 74 61 63 6b 73 } //1 kill_attacks
		$a_00_3 = {63 6d 64 5f 6e 6f 74 5f 61 74 74 61 63 6b } //1 cmd_not_attack
		$a_00_4 = {6b 69 6c 6c 65 72 5f 72 75 6e } //1 killer_run
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}