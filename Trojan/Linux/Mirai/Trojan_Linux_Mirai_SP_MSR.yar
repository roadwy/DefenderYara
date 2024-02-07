
rule Trojan_Linux_Mirai_SP_MSR{
	meta:
		description = "Trojan:Linux/Mirai.SP!MSR,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 6b 5f 67 65 74 5f 6f 70 74 5f 69 6e 74 } //01 00  attack_get_opt_int
		$a_00_1 = {6b 69 6c 6c 65 72 5f 6b 69 6c 6c 5f 62 79 5f 70 6f 72 74 } //01 00  killer_kill_by_port
		$a_00_2 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 5f 73 74 64 } //01 00  attack_method_std
		$a_00_3 = {6b 69 6c 6c 65 72 5f 70 69 64 } //00 00  killer_pid
	condition:
		any of ($a_*)
 
}