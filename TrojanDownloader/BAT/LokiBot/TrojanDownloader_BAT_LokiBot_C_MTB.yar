
rule TrojanDownloader_BAT_LokiBot_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/LokiBot.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {06 16 06 8e 69 28 } //1
		$a_03_1 = {02 28 06 00 00 06 0a 06 73 90 01 01 00 00 0a 0b 00 07 20 80 f0 fa 02 6f 90 01 01 00 00 0a 0c de 0b 07 2c 07 07 6f 90 01 01 00 00 0a 00 dc 90 00 } //1
		$a_01_2 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
		$a_01_4 = {57 65 62 52 65 73 70 6f 6e 73 65 } //1 WebResponse
		$a_01_5 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_6 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_8 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}