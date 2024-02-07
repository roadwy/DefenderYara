
rule TrojanDownloader_BAT_RedLineStealer_KB_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 00 08 6f 90 01 03 0a 00 16 2d 90 01 01 06 08 6f 90 01 03 0a 16 08 6f 90 01 03 0a 8e 69 6f 90 01 03 0a 00 06 0d 90 0a 46 00 72 90 01 03 70 2b 90 01 01 2b 90 01 01 2b 90 01 01 2b 90 01 01 20 90 01 03 05 2b 90 01 01 2b 90 01 01 73 90 01 03 0a 0c 08 07 6f 90 00 } //01 00 
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00  GetResponse
		$a_01_3 = {52 65 61 64 42 79 74 65 73 } //01 00  ReadBytes
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_5 = {57 65 62 52 65 73 70 6f 6e 73 65 } //00 00  WebResponse
	condition:
		any of ($a_*)
 
}