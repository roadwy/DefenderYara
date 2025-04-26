
rule TrojanDownloader_O97M_Obfuse_YBA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YBA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 77 72 20 68 74 74 70 3a 2f 2f 77 65 65 73 68 6f 70 70 69 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 49 44 33 2f 7a 2f 37 36 30 32 30 2e 6a 70 67 } //1 iwr http://weeshoppi.com/wp-includes/ID3/z/76020.jpg
		$a_01_1 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 70 71 61 76 76 79 68 2e 65 78 65 } //1 Start-Process -FilePath "C:\Users\Public\pqavvyh.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}