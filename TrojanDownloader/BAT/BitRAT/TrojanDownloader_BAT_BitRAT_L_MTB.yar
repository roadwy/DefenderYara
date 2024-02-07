
rule TrojanDownloader_BAT_BitRAT_L_MTB{
	meta:
		description = "TrojanDownloader:BAT/BitRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a dc 02 6f 90 01 01 00 00 0a 18 5b 8d 90 01 01 00 00 01 0d 16 09 8e 69 28 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00  GetResponse
		$a_01_4 = {67 65 74 5f 55 54 46 38 } //00 00  get_UTF8
	condition:
		any of ($a_*)
 
}