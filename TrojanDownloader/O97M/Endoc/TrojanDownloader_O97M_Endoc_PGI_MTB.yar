
rule TrojanDownloader_O97M_Endoc_PGI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Endoc.PGI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 } //1 /c powershell -command
		$a_00_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_00_2 = {68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 61 79 62 69 6f 74 61 2f 6d 70 62 68 33 33 37 37 35 2f 67 68 2d 70 61 67 65 73 2f 67 39 77 6c 35 64 70 2e 74 74 66 } //1 https://raw.githubusercontent.com/aybiota/mpbh33775/gh-pages/g9wl5dp.ttf
		$a_03_3 = {25 74 6d 70 25 5c 5c 90 02 0a 2e 6a 61 72 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}