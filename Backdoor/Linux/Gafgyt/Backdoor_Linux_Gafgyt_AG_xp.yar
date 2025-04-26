
rule Backdoor_Linux_Gafgyt_AG_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AG!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 6f 72 5f 61 64 64 5f 73 6f 63 6b } //1 tor_add_sock
		$a_01_1 = {74 63 70 72 61 77 } //1 tcpraw
		$a_01_2 = {75 64 70 70 6c 61 69 6e } //1 udpplain
		$a_01_3 = {6d 61 69 6e 5f 69 6e 73 74 61 6e 63 65 5f 6b 69 6c 6c } //1 main_instance_kill
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}