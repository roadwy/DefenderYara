
rule TrojanDownloader_O97M_Powdow_QTR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.QTR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 66 73 6f 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 62 69 2e 62 61 74 22 2c 20 57 52 2c 20 54 72 75 65 29 } //1 = fso.OpenTextFile("C:\Windows\Temp\bi.bat", WR, True)
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e } //1 powershell.exe -ExecutionPolicy bypass -noprofile -windowstyle hidden
		$a_01_2 = {2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 2e 65 65 2f 72 2f 34 41 49 6c 30 27 29 } //1 .DownloadString('https://paste.ee/r/4AIl0')
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}