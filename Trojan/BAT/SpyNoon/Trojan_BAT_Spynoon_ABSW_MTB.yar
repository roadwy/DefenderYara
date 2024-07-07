
rule Trojan_BAT_Spynoon_ABSW_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ABSW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 04 2b 09 de 0d 28 90 01 01 00 00 06 2b f5 0a 2b f4 26 de ec 90 00 } //2
		$a_03_1 = {2b 05 2b 06 2b 0b 2a 02 2b f8 28 90 01 01 00 00 2b 2b f3 28 90 01 01 00 00 2b 2b ee 90 00 } //2
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}