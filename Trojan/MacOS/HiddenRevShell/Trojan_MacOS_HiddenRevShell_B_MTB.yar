
rule Trojan_MacOS_HiddenRevShell_B_MTB{
	meta:
		description = "Trojan:MacOS/HiddenRevShell.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {bf 02 00 00 00 be 01 00 00 00 31 d2 e8 } //1
		$a_01_1 = {89 df ba 10 00 00 00 e8 } //1
		$a_03_2 = {48 89 f3 41 89 fe 31 f6 e8 ?? ?? ?? ?? 6a 01 41 5f 44 89 f7 44 89 fe e8 ?? ?? ?? ?? 6a 02 5e } //2
		$a_03_3 = {89 df 31 f6 e8 ?? ?? ?? ?? 89 df be 01 00 00 00 e8 c7 01 00 00 89 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=4
 
}