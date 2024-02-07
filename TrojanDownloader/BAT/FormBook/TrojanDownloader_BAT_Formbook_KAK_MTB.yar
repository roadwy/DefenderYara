
rule TrojanDownloader_BAT_Formbook_KAK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 06 90 02 02 91 61 d2 9c 2b 03 0c 2b 90 01 01 90 02 02 17 58 90 02 02 2b 03 0b 2b 90 01 01 90 02 02 06 8e 69 32 90 00 } //01 00 
		$a_03_1 = {00 00 0a 25 02 73 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0a 6f 90 01 01 00 00 0a 06 0b de 90 00 } //01 00 
		$a_01_2 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_3 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_5 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //01 00  CreateDelegate
		$a_01_6 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //00 00  DynamicInvoke
	condition:
		any of ($a_*)
 
}