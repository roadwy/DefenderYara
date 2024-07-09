
rule TrojanDownloader_BAT_LokiBot_EZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/LokiBot.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {09 12 04 28 ?? ?? ?? 0a [0-01] 07 08 02 08 91 6f ?? ?? ?? 0a [0-01] de ?? 11 04 2c ?? 09 28 ?? ?? ?? 0a [0-01] dc } //10
		$a_03_1 = {12 01 23 00 00 00 00 00 00 24 40 28 ?? ?? ?? 0a 0d 2b 02 00 00 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 11 04 2d ed } //1
		$a_03_2 = {12 01 23 00 00 00 00 00 00 24 40 28 ?? ?? ?? 0a 1d 2d 06 26 2b 06 0b 2b e7 0a 2b 00 06 28 ?? ?? ?? 0a } //1
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}