
rule Trojan_BAT_Formbook_ME_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 06 08 6f 90 01 03 90 0a 22 00 07 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 90 02 0a 06 18 6f 90 01 03 0a 00 02 0d 06 6f 90 01 03 0a 09 16 09 8e 69 6f 90 01 03 0a 13 04 de 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_4 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_6 = {73 65 74 5f 4b 65 79 } //00 00  set_Key
	condition:
		any of ($a_*)
 
}