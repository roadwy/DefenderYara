
rule Trojan_Linux_ProcessHider_A_MTB{
	meta:
		description = "Trojan:Linux/ProcessHider.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 69 64 65 5f 74 63 70 5f 70 6f 72 74 73 } //1 hide_tcp_ports
		$a_00_1 = {2f 61 70 70 2f 69 73 5f 68 69 64 64 65 6e 5f 66 69 6c 65 2e 63 } //1 /app/is_hidden_file.c
		$a_00_2 = {69 73 5f 61 74 74 61 63 6b 65 72 } //1 is_attacker
		$a_00_3 = {67 65 74 5f 70 72 6f 63 65 73 73 5f 6e 61 6d 65 } //1 get_process_name
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}