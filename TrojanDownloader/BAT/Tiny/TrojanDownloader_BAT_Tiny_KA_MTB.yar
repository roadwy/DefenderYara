
rule TrojanDownloader_BAT_Tiny_KA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0b 07 72 ?? 00 00 70 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 0c 08 06 28 ?? 00 00 0a 08 28 ?? 00 00 0a 26 2a } //10
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_4 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}