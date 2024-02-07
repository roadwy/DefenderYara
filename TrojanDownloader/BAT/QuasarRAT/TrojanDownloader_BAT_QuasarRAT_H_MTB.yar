
rule TrojanDownloader_BAT_QuasarRAT_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 25 d0 01 00 00 04 90 01 01 2d 0e 26 26 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 2b 07 28 90 01 01 00 00 0a 2b ed 2a 90 00 } //02 00 
		$a_03_1 = {07 08 18 5b 02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 08 18 58 0c 08 06 90 00 } //01 00 
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00  GetResponse
		$a_01_3 = {52 65 61 64 54 6f 45 6e 64 } //01 00  ReadToEnd
		$a_01_4 = {67 65 74 5f 4c 65 6e 67 74 68 } //01 00  get_Length
		$a_01_5 = {67 65 74 5f 55 54 46 38 } //01 00  get_UTF8
		$a_01_6 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}