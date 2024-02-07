
rule Backdoor_BAT_Bladabindi_ABH_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0d 00 00 03 00 "
		
	strings :
		$a_03_0 = {08 1b 62 08 58 11 04 61 0c 11 05 18 58 49 13 04 11 04 39 1d 90 01 02 00 09 1b 62 09 58 11 04 61 0d 11 05 18 d3 18 5a 58 13 05 90 00 } //01 00 
		$a_01_1 = {63 68 72 6f 6d 65 4b 65 79 } //01 00  chromeKey
		$a_01_2 = {45 6e 63 72 79 70 74 65 64 44 61 74 61 } //01 00  EncryptedData
		$a_01_3 = {47 65 74 46 69 6c 65 73 } //01 00  GetFiles
		$a_01_4 = {47 65 74 42 72 6f 77 73 65 72 73 } //01 00  GetBrowsers
		$a_01_5 = {47 65 74 44 65 66 61 75 6c 74 49 50 76 34 41 64 64 72 65 73 73 } //01 00  GetDefaultIPv4Address
		$a_01_6 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  AesCryptoServiceProvider
		$a_01_7 = {44 65 62 75 67 67 65 72 } //01 00  Debugger
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_9 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_01_10 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_11 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //01 00  WriteAllBytes
		$a_01_12 = {47 65 74 49 50 50 72 6f 70 65 72 74 69 65 73 } //00 00  GetIPProperties
	condition:
		any of ($a_*)
 
}