
rule Backdoor_Linux_Gafgyt_AQ_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {73 63 61 6e 6e 65 72 5f 6b 69 6c 6c } //1 scanner_kill
		$a_01_1 = {62 6f 74 6e 65 74 5f 62 75 69 6c 64 } //1 botnet_build
		$a_01_2 = {62 6f 74 6e 65 74 5f 69 64 } //1 botnet_id
		$a_01_3 = {63 6f 6e 6e 65 63 74 5f 63 6e 63 } //1 connect_cnc
		$a_01_4 = {61 74 74 61 63 6b 5f 70 74 63 70 } //1 attack_ptcp
		$a_01_5 = {61 74 74 61 63 6b 5f 70 75 64 70 } //1 attack_pudp
		$a_01_6 = {61 74 74 61 63 6b 5f 73 74 61 72 74 } //1 attack_start
		$a_01_7 = {61 74 74 61 63 6b 5f 73 74 6f 70 } //1 attack_stop
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}