
rule TrojanDownloader_O97M_EncDoc_NJR_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.NJR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 78 6a 63 71 75 78 79 } //1 https://tinyurl.com/yxjcquxy
		$a_01_1 = {43 3a 5c 50 52 4f 47 52 41 4d 44 41 54 41 5c 61 2e 76 62 73 } //1 C:\PROGRAMDATA\a.vbs
		$a_01_2 = {4a 4a 43 43 4a 4a } //1 JJCCJJ
		$a_01_3 = {45 78 65 63 75 74 65 41 } //1 ExecuteA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}