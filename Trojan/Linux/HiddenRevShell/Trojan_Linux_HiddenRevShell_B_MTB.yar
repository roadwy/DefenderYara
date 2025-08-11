
rule Trojan_Linux_HiddenRevShell_B_MTB{
	meta:
		description = "Trojan:Linux/HiddenRevShell.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 f6 89 df e8 ?? ?? ?? ?? be 01 00 00 00 89 df e8 ?? ?? ?? ?? be 02 00 00 00 89 df e8 } //2
		$a_01_1 = {48 89 e6 ba 10 00 00 00 89 df 89 44 24 04 e8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}