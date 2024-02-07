
rule Trojan_BAT_Bladabindi_MBIB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {13 04 2b 19 09 06 16 11 04 6f 90 01 01 00 00 0a 00 07 06 16 06 8e b7 6f 90 01 01 00 00 0a 13 04 00 11 04 16 fe 02 13 06 11 06 2d dc 90 00 } //01 00 
		$a_01_1 = {34 64 39 38 2d 62 65 39 65 2d 37 33 65 36 66 31 39 33 34 30 31 63 } //01 00  4d98-be9e-73e6f193401c
		$a_01_2 = {47 00 65 00 74 00 54 00 79 00 70 00 65 00 73 00 } //01 00  GetTypes
		$a_01_3 = {4d 49 2e 65 78 65 } //01 00  MI.exe
		$a_01_4 = {41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //01 00  Assembly
		$a_01_5 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}