
rule TrojanSpy_BAT_AveMaria_MTB{
	meta:
		description = "TrojanSpy:BAT/AveMaria!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 06 00 "
		
	strings :
		$a_03_0 = {0c 04 00 fe 90 01 02 00 fe 90 01 02 00 fe 90 01 02 00 91 fe 90 01 02 00 61 d2 9c 00 fe 90 01 02 00 20 90 01 03 00 58 fe 90 01 02 00 fe 90 01 02 00 fe 90 01 02 00 8e 69 fe 90 01 01 fe 90 01 02 00 fe 90 01 02 00 3a 90 01 02 ff ff 90 00 } //01 00 
		$a_01_1 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_2 = {6c 6f 63 61 6c 46 69 6c 65 50 61 74 68 } //01 00  localFilePath
		$a_01_3 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_4 = {45 78 74 72 61 63 74 52 65 73 6f 75 72 63 65 54 6f 52 6f 6f 74 50 61 74 68 } //01 00  ExtractResourceToRootPath
		$a_01_5 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}