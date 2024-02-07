
rule Trojan_BAT_RedLineStealer_MAZ_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 0d 6a 59 13 05 90 0a 20 00 09 69 8d 90 01 03 01 25 17 28 90 01 03 06 13 04 06 28 90 01 03 06 90 02 06 07 06 11 04 11 05 09 6f 90 01 03 06 2a 90 00 } //01 00 
		$a_01_1 = {49 73 4c 6f 67 67 69 6e 67 } //01 00  IsLogging
		$a_01_2 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_4 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 } //01 00  Debugger
		$a_81_8 = {73 64 66 73 64 } //00 00  sdfsd
	condition:
		any of ($a_*)
 
}