
rule TrojanDownloader_O97M_EncDoc_CHS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.CHS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 70 69 63 6b 74 68 69 73 6d 6f 74 65 6c 2e 78 79 7a 2f 63 61 6d 70 6f 2f 62 2f 62 } //1 http://pickthismotel.xyz/campo/b/b
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 62 69 77 61 5c 77 64 2e 65 78 65 } //1 C:\Users\Public\biwa\wd.exe
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}