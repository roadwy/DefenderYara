
rule Trojan_Linux_Mirai_B_MTB{
	meta:
		description = "Trojan:Linux/Mirai.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 2e 63 } //1 attack_method.c
		$a_00_1 = {61 74 74 61 63 6b 5f 6b 69 6c 6c 5f 61 6c 6c } //1 attack_kill_all
		$a_00_2 = {6b 69 6c 6c 65 72 5f 72 65 61 6c 70 61 74 68 } //1 killer_realpath
		$a_00_3 = {6b 69 6c 6c 65 72 5f 6b 69 6c 6c 5f 62 79 5f 70 6f 72 74 } //1 killer_kill_by_port
		$a_00_4 = {61 74 74 61 63 6b 5f 67 65 74 5f 6f 70 74 5f 69 70 } //1 attack_get_opt_ip
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}