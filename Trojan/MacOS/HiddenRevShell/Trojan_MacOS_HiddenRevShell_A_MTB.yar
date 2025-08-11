
rule Trojan_MacOS_HiddenRevShell_A_MTB{
	meta:
		description = "Trojan:MacOS/HiddenRevShell.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 00 80 52 21 00 80 52 02 00 80 52 d9 } //1
		$a_01_1 = {e0 1f 00 b9 e1 63 00 91 e0 03 13 aa 02 02 80 52 a9 } //1
		$a_03_2 = {f4 03 00 aa 01 00 80 52 61 ?? ?? ?? e0 03 14 aa 21 00 80 52 5e ?? ?? ?? e0 03 14 aa 41 00 80 52 5b } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}