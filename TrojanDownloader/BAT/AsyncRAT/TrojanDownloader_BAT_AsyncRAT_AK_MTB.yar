
rule TrojanDownloader_BAT_AsyncRAT_AK_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {0a 13 07 08 07 02 11 07 18 5a 18 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 09 6f 90 00 } //2
		$a_01_1 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_5 = {67 65 74 5f 55 54 46 38 } //1 get_UTF8
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}