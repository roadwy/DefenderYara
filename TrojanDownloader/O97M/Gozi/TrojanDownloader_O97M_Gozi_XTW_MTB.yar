
rule TrojanDownloader_O97M_Gozi_XTW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.XTW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 65 72 76 69 63 65 2e 74 65 63 68 6e 6f 73 6f 6c 61 72 73 79 73 74 65 6d 73 2e 63 6f 6d 2f 69 6e 73 74 61 6c 6c 61 7a 69 6f 6e 65 2e 64 6c 6c } //1 http://service.technosolarsystems.com/installazione.dll
		$a_01_1 = {7a 6c 70 50 45 42 75 2e 64 6c 6c } //1 zlpPEBu.dll
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_3 = {43 3a 5c 4e 4b 68 44 62 68 64 5c 70 73 48 63 65 6e 78 } //1 C:\NKhDbhd\psHcenx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}