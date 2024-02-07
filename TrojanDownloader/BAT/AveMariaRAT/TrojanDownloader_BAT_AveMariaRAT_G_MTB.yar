
rule TrojanDownloader_BAT_AveMariaRAT_G_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0b 07 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c 06 08 6f 90 01 01 00 00 0a 06 18 6f 90 01 01 00 00 0a 20 90 01 03 00 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 0d 06 6f 90 01 01 00 00 0a 09 16 09 8e 69 6f 90 00 } //02 00 
		$a_03_1 = {00 00 0a 0b 06 07 6f 90 01 01 00 00 0a 0c de 90 00 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_4 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //01 00  CreateDelegate
		$a_01_5 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //00 00  DynamicInvoke
	condition:
		any of ($a_*)
 
}