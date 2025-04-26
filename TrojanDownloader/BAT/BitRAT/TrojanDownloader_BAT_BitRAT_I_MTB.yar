
rule TrojanDownloader_BAT_BitRAT_I_MTB{
	meta:
		description = "TrojanDownloader:BAT/BitRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_03_0 = {0c 08 06 6f ?? 00 00 0a 0d 07 09 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 02 13 04 07 6f ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 dd } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_5 = {54 6f 4c 69 73 74 } //1 ToList
		$a_01_6 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}