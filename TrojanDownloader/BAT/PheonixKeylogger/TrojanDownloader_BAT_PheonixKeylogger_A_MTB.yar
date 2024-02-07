
rule TrojanDownloader_BAT_PheonixKeylogger_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/PheonixKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {70 38 85 00 00 00 38 8a 00 00 00 38 8b 00 00 00 38 8c 00 00 00 38 91 00 00 00 00 73 90 01 01 00 00 0a 0c 00 2b 31 16 2b 31 2b 36 2b 3b 00 09 08 6f 90 01 01 00 00 0a 00 00 de 90 00 } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_01_4 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_5 = {54 6f 4c 69 73 74 } //01 00  ToList
		$a_01_6 = {4f 70 65 6e 52 65 61 64 } //01 00  OpenRead
		$a_01_7 = {43 6f 70 79 54 6f } //00 00  CopyTo
	condition:
		any of ($a_*)
 
}