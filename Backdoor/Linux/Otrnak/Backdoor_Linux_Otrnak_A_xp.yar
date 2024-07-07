
rule Backdoor_Linux_Otrnak_A_xp{
	meta:
		description = "Backdoor:Linux/Otrnak.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6e 67 61 6d 65 20 63 6f 6e 74 72 6c } //2 cngame contrl
		$a_01_1 = {43 6e 67 61 6d 65 20 43 6f 6d 6d 61 6e 64 } //1 Cngame Command
		$a_01_2 = {63 6e 67 61 6d 65 73 68 65 6c 6c } //1 cngameshell
		$a_01_3 = {69 63 6d 70 5f 73 68 65 6c 6c } //1 icmp_shell
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}