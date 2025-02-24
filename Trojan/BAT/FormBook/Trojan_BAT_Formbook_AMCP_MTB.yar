
rule Trojan_BAT_Formbook_AMCP_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 08 28 ?? 00 00 06 a2 28 ?? 00 00 0a 75 } //4
		$a_01_1 = {34 00 44 00 35 00 41 00 39 00 3a 00 30 00 33 00 3a 00 3a 00 30 00 34 00 3a 00 3a 00 46 00 46 00 46 00 46 00 3a 00 30 00 42 00 38 00 3a 00 3a 00 3a 00 3a 00 30 00 30 00 34 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a } //4
		$a_01_2 = {4c 00 6f 00 67 00 69 00 6e 00 00 09 4c 00 6f 00 61 00 64 00 } //2 LoginऀLoad
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2) >=10
 
}