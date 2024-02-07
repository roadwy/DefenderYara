
rule TrojanDownloader_BAT_RedLineStealer_KA_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 8e 69 28 90 01 03 0a 00 28 90 01 03 0a 7e 90 01 03 04 6f 90 01 03 0a 26 00 2a 90 0a 26 00 7e 90 01 03 04 16 7e 90 00 } //01 00 
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00  GetResponse
		$a_01_3 = {52 65 61 64 42 79 74 65 73 } //01 00  ReadBytes
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}