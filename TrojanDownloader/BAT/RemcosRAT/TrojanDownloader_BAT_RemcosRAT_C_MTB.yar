
rule TrojanDownloader_BAT_RemcosRAT_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/RemcosRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0a 00 06 02 6f 90 01 03 0a 0b 00 73 90 01 03 0a 0c 00 07 08 6f 90 01 03 0a 00 08 6f 90 01 03 0a 0d de 90 00 } //01 00 
		$a_03_1 = {0a 0c 00 08 07 90 0a 1f 00 02 73 90 01 03 0a 0a 00 73 90 01 03 0a 0b 00 06 16 73 90 01 03 0a 73 90 00 } //01 00 
		$a_03_2 = {0a 0b 00 07 6f 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 0c 08 2c 90 01 01 07 0d de 90 00 } //01 00 
		$a_01_3 = {43 6f 70 79 54 6f } //01 00  CopyTo
		$a_01_4 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 73 } //01 00  GetMethods
		$a_01_6 = {54 6f 4c 69 73 74 } //00 00  ToList
	condition:
		any of ($a_*)
 
}