
rule Trojan_Linux_HCRootkit_B{
	meta:
		description = "Trojan:Linux/HCRootkit.B,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 69 64 65 5f 70 72 6f 63 } //1 hide_proc
		$a_00_1 = {73 5f 68 69 64 65 5f 70 69 64 73 } //1 s_hide_pids
		$a_00_2 = {73 5f 69 6e 6c 5f 65 6e 74 72 79 } //1 s_inl_entry
		$a_00_3 = {72 6f 6f 74 6b 69 74 } //1 rootkit
		$a_00_4 = {73 5f 68 69 64 65 5f 74 63 70 34 5f 70 6f 72 74 73 } //1 s_hide_tcp4_ports
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}