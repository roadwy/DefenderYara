
rule Trojan_BAT_zgRAT_E_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0d 08 73 90 01 01 00 00 0a 13 04 11 04 07 16 73 90 01 01 00 00 0a 13 05 11 05 09 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 13 06 de 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}