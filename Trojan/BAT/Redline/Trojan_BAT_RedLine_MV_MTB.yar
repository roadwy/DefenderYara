
rule Trojan_BAT_RedLine_MV_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 16 06 8e 69 6f 90 01 03 0a 0d 09 8e 69 1f 10 59 8d 90 01 03 01 13 04 09 1f 10 11 04 16 09 8e 69 1f 10 59 28 90 01 03 0a 00 11 04 28 90 01 03 06 28 90 01 03 06 6f 90 01 03 0a 17 9a 80 90 01 03 04 02 13 05 2b 00 11 05 2a 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {55 73 65 72 43 6f 6e 74 72 6f 6c } //01 00  UserControl
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}