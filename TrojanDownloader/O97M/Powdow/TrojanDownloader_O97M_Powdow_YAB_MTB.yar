
rule TrojanDownloader_O97M_Powdow_YAB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.YAB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 66 65 6e 78 62 7a 74 64 68 2e 65 78 65 } //02 00  Start-Process -FilePath "C:\Users\Public\fenxbztdh.exe
		$a_00_1 = {69 77 72 20 68 74 74 70 3a 2f 2f 37 39 2e 31 34 31 2e 31 36 35 2e 31 37 33 2f 44 58 2f 46 44 2d 32 30 35 38 31 2e 6a 70 67 20 2d 4f 75 74 46 69 6c 65 } //00 00  iwr http://79.141.165.173/DX/FD-20581.jpg -OutFile
	condition:
		any of ($a_*)
 
}