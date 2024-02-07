
rule TrojanDownloader_BAT_QuasarRAT_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 08 00 00 06 13 00 38 00 00 00 00 11 00 28 06 00 00 06 38 } //01 00 
		$a_03_1 = {20 dc 27 00 00 8d 07 00 00 01 13 90 01 01 38 90 0a 21 00 11 02 6f 90 01 01 00 00 0a 13 03 38 90 00 } //01 00 
		$a_01_2 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_3 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_4 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //01 00  SecurityProtocolType
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_6 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_01_7 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  HttpWebResponse
		$a_01_8 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_9 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_10 = {47 65 74 4d 65 74 68 6f 64 73 } //00 00  GetMethods
	condition:
		any of ($a_*)
 
}