
rule Trojan_Linux_HiddenRevShell_A_MTB{
	meta:
		description = "Trojan:Linux/HiddenRevShell.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 cc 48 8d 4d d0 8b 45 cc ba 10 00 00 00 48 89 ce 89 c7 e8 } //2
		$a_01_1 = {48 89 45 e0 48 c7 45 e8 00 00 00 00 48 8d 45 e0 ba 00 00 00 00 48 89 c6 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}