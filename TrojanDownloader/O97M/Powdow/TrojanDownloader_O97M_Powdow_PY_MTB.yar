
rule TrojanDownloader_O97M_Powdow_PY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //01 00  powershell.exe -WindowStyle Hidden
		$a_00_1 = {68 74 74 70 3a 2f 2f 31 38 35 2e 31 38 33 2e 39 38 2e 32 34 36 2f 31 35 30 2f 44 4c 2d 31 33 33 30 36 2e 6a 70 67 } //01 00  http://185.183.98.246/150/DL-13306.jpg
		$a_00_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 } //01 00  Start-Process -FilePath
		$a_00_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 69 71 69 6c 71 6f 6c 62 6c 2e 65 78 65 } //01 00  C:\Users\Public\Documents\iqilqolbl.exe
		$a_00_4 = {77 69 6e 6d 67 6d 74 73 3a 77 69 6e 33 32 5f 50 72 6f 63 65 73 73 } //00 00  winmgmts:win32_Process
	condition:
		any of ($a_*)
 
}