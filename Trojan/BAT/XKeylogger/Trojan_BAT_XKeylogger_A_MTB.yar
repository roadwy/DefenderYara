
rule Trojan_BAT_XKeylogger_A_MTB{
	meta:
		description = "Trojan:BAT/XKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 00 01 14 14 14 28 } //2
		$a_01_1 = {00 00 01 13 4d 11 4d 16 14 a2 } //2
		$a_01_2 = {11 4d 17 14 a2 } //2
		$a_01_3 = {11 4d 14 14 14 28 } //2 䴑ᐔ⠔
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}