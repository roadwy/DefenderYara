
rule TrojanDownloader_O97M_EncDoc_S_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.S!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 6c 7a 68 79 6b 6f 6f 2e 65 78 65 } //1 c:\programdata\lzhykoo.exe
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}