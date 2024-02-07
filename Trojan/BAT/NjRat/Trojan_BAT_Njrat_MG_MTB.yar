
rule Trojan_BAT_Njrat_MG_MTB{
	meta:
		description = "Trojan:BAT/Njrat.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 04 03 09 6f 90 01 03 0a 13 06 12 06 28 90 01 03 0a 6f 90 01 03 0a 03 09 6f 90 01 03 0a 28 90 01 03 0a 16 28 90 01 03 0a 16 fe 01 fe 01 13 05 11 05 2c 1e 07 03 09 6f 90 01 03 0a 13 06 12 06 28 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 26 2b 0e 07 03 09 6f 90 01 03 0a 6f 90 01 03 0a 26 00 09 17 d6 0d 09 08 3e 3e 90 00 } //01 00 
		$a_01_1 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00  GetFolderPath
		$a_01_2 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_3 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}