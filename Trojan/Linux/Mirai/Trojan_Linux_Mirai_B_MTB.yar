
rule Trojan_Linux_Mirai_B_MTB{
	meta:
		description = "Trojan:Linux/Mirai.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 2e 63 } //01 00  attack_method.c
		$a_00_1 = {61 74 74 61 63 6b 5f 6b 69 6c 6c 5f 61 6c 6c } //01 00  attack_kill_all
		$a_00_2 = {6b 69 6c 6c 65 72 5f 72 65 61 6c 70 61 74 68 } //01 00  killer_realpath
		$a_00_3 = {6b 69 6c 6c 65 72 5f 6b 69 6c 6c 5f 62 79 5f 70 6f 72 74 } //01 00  killer_kill_by_port
		$a_00_4 = {61 74 74 61 63 6b 5f 67 65 74 5f 6f 70 74 5f 69 70 } //00 00  attack_get_opt_ip
		$a_00_5 = {5d 04 00 } //00 1f 
	condition:
		any of ($a_*)
 
}