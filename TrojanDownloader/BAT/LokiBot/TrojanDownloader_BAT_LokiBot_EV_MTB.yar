
rule TrojanDownloader_BAT_LokiBot_EV_MTB{
	meta:
		description = "TrojanDownloader:BAT/LokiBot.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 91 6f 90 01 03 0a 07 25 17 59 19 2d 0a 26 16 fe 02 0c 08 2d e7 90 00 } //1
		$a_01_1 = {26 12 01 23 00 00 00 00 00 00 35 40 28 1b 00 00 0a 19 2d 06 26 2b 06 0b 2b e7 0a 2b 00 06 28 } //1
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}