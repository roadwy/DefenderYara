
rule Trojan_BAT_Formbook_MO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 04 17 13 05 2b 35 07 11 05 17 da 6f 90 01 03 0a 08 11 05 08 6f 90 01 03 0a 5d 6f 90 01 03 0a da 13 06 09 11 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0d 11 05 17 d6 13 05 11 05 11 04 31 c5 09 0a 2b 00 06 2a 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 } //01 00  Create__Instance
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}