
rule TrojanDownloader_O97M_Donoff_RBQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RBQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6e 61 62 68 61 7a 65 6e 61 2e 6f 72 67 2f 63 6f 6e 74 65 6e 74 2f 73 6c 69 64 65 73 2f 69 6d 61 67 65 2f 61 70 70 2f 50 52 4f 4c 45 41 4b 2e 65 78 65 90 0a 3a 00 68 74 74 70 73 3a 2f 2f } //1
		$a_01_1 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6a 7a 77 72 78 62 68 6c 63 2e 65 78 65 22 } //1 Start-Process -FilePath "C:\Users\Public\Documents\jzwrxbhlc.exe"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}