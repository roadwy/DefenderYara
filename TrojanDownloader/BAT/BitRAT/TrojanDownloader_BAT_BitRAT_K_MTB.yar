
rule TrojanDownloader_BAT_BitRAT_K_MTB{
	meta:
		description = "TrojanDownloader:BAT/BitRAT.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 06 20 e8 03 00 00 73 90 01 01 00 00 0a 0d 08 09 08 6f 90 01 01 00 00 0a 1e 5b 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 08 09 08 6f 90 01 01 00 00 0a 1e 5b 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 08 17 6f 90 00 } //02 00 
		$a_03_1 = {0a 13 04 11 04 02 16 02 8e 69 6f 90 01 01 00 00 0a 11 04 6f 90 00 } //01 00 
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_3 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_4 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //00 00  GetResponseStream
	condition:
		any of ($a_*)
 
}