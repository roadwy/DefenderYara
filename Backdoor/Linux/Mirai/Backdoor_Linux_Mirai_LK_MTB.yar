
rule Backdoor_Linux_Mirai_LK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 65 72 5f 77 69 70 65 5f 73 74 72 69 6e 67 73 } //1 killer_wipe_strings
		$a_01_1 = {61 74 74 61 63 6b 5f 67 72 65 2e 63 } //1 attack_gre.c
		$a_01_2 = {6e 65 77 62 6f 74 5f 76 31 } //1 newbot_v1
		$a_01_3 = {61 74 74 61 63 6b 5f 72 65 61 70 5f 64 65 61 64 } //1 attack_reap_dead
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}