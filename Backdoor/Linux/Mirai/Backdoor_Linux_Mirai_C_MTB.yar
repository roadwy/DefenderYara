
rule Backdoor_Linux_Mirai_C_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 65 72 5f 6b 69 6c 6c 5f 62 79 5f 70 6f 72 74 } //1 killer_kill_by_port
		$a_00_1 = {61 74 74 61 63 6b 5f 67 65 74 5f 6f 70 74 5f 69 70 } //1 attack_get_opt_ip
		$a_00_2 = {61 74 74 61 63 6b 5f 75 64 70 5f 64 6e 73 } //1 attack_udp_dns
		$a_00_3 = {61 6e 74 69 5f 67 64 62 5f 65 6e 74 72 79 } //1 anti_gdb_entry
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}