
rule TrojanDownloader_BAT_RemcosRAT_D_MTB{
	meta:
		description = "TrojanDownloader:BAT/RemcosRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 09 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 00 73 90 01 03 0a 0c 16 2d 90 01 01 00 2b 90 01 01 2b 90 01 01 2b 90 01 01 00 2b 90 01 01 2b 90 01 01 16 2c 90 01 01 26 de 90 01 01 07 2b 90 01 01 08 2b 90 01 01 6f 90 01 03 0a 2b 90 01 01 08 2b 90 01 01 6f 90 01 03 0a 2b 90 01 01 0d 2b 90 0a 4a 00 17 2c 90 01 01 00 2b 90 01 01 38 90 01 03 00 00 06 02 6f 90 00 } //15
		$a_01_1 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_2 = {54 6f 4c 69 73 74 } //1 ToList
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_4 = {42 75 66 66 65 72 65 64 53 74 72 65 61 6d } //1 BufferedStream
		$a_01_5 = {43 6f 70 79 54 6f } //1 CopyTo
		$a_01_6 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_7 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
		$a_01_8 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=22
 
}