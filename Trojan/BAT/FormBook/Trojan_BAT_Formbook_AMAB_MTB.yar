
rule Trojan_BAT_Formbook_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 04 05 28 ?? 00 00 06 0a 0e ?? 03 6f ?? 00 00 0a 59 0b 03 06 07 28 ?? 00 00 06 2a } //4
		$a_01_1 = {4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}
rule Trojan_BAT_Formbook_AMAB_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 8e 69 5d 13 05 11 04 08 6f ?? 00 00 0a 5d 13 06 07 11 05 91 13 07 08 11 06 6f ?? 00 00 0a 13 08 02 07 11 04 28 ?? 00 00 06 13 09 02 11 07 11 08 11 09 28 ?? 00 00 06 13 0a 07 11 05 02 11 0a 28 ?? 00 00 06 9c 11 04 17 59 13 04 11 04 16 2f ad } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}