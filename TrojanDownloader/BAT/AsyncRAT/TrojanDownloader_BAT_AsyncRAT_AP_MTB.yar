
rule TrojanDownloader_BAT_AsyncRAT_AP_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_03_0 = {0a 10 00 02 6f ?? 00 00 0a 18 5b 8d ?? 00 00 01 0a 16 0b 2b 18 06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 07 17 58 0b 07 06 8e 69 32 } //2
		$a_03_1 = {0a 20 00 0f 00 00 60 28 ?? 00 00 0a 72 } //2
		$a_01_2 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_01_3 = {67 65 74 5f 41 53 43 49 49 } //1 get_ASCII
		$a_01_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_5 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 } //1 Download
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}