
rule Trojan_Linux_Vlany_A_xp{
	meta:
		description = "Trojan:Linux/Vlany.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 69 64 65 5f 76 6c 61 6e 79 } //1 hide_vlany
		$a_01_1 = {68 69 64 64 65 6e 5f 70 6f 72 74 73 } //1 hidden_ports
		$a_01_2 = {2f 74 6d 70 2f 2e 58 58 48 } //1 /tmp/.XXH
		$a_01_3 = {75 6e 68 69 64 65 5f 70 72 6f 63 } //1 unhide_proc
		$a_01_4 = {2f 70 72 6f 63 2f 2a 2f 6e 75 6d 61 5f 6d 61 70 73 } //1 /proc/*/numa_maps
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}