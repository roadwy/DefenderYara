
rule TrojanDownloader_BAT_AsyncRAT_K_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d6 0c 08 11 90 01 01 13 90 01 01 11 90 01 01 31 90 01 01 7e 90 01 03 04 6f 90 01 03 0a 90 0a 34 00 7e 90 01 03 04 07 08 16 6f 90 01 03 0a 13 90 01 01 12 90 01 01 28 90 01 03 0a 6f 90 01 03 0a 00 00 08 17 90 00 } //01 00 
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } //00 00  WebClient
	condition:
		any of ($a_*)
 
}