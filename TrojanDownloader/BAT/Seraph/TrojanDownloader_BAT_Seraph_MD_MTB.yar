
rule TrojanDownloader_BAT_Seraph_MD_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_03_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 39 00 31 00 2e 00 32 00 34 00 33 00 2e 00 34 00 34 00 2e 00 31 00 39 00 2f 00 [0-10] 2e 00 6a 00 70 00 65 00 67 00 } //1
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}