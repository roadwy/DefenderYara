
rule TrojanDownloader_BAT_Nekark_ABNY_MTB{
	meta:
		description = "TrojanDownloader:BAT/Nekark.ABNY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {70 2b 24 2b 29 2b 2e 2b 33 2b 34 16 2b 34 8e 69 17 2d 32 26 26 26 1d 2c 02 07 0c 16 2d dc de 55 28 90 01 03 0a 2b d5 28 90 01 03 06 2b d5 6f 90 01 03 0a 2b d0 28 90 01 03 0a 2b cb 0b 2b ca 07 2b c9 07 2b c9 28 90 01 03 0a 2b ca 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}