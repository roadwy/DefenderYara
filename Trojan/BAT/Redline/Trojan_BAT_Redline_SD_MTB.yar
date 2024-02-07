
rule Trojan_BAT_Redline_SD_MTB{
	meta:
		description = "Trojan:BAT/Redline.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 09 6f 39 00 00 0a 28 90 01 03 0a 13 04 11 04 28 90 01 03 0a 20 90 01 04 da 13 05 11 05 28 90 01 03 0a 28 90 01 04 13 06 07 11 06 28 90 01 03 0a 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 07 11 07 90 00 } //01 00 
		$a_01_1 = {45 5a 4d 4f 45 70 4a 44 44 66 } //01 00  EZMOEpJDDf
		$a_01_2 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 } //01 00  get_Computer
		$a_01_3 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_4 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //00 00  WriteAllBytes
	condition:
		any of ($a_*)
 
}