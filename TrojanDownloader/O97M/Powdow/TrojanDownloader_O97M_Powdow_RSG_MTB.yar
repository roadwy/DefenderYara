
rule TrojanDownloader_O97M_Powdow_RSG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RSG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {61 69 6d 73 6d 6f 74 69 6f 6e 2e 63 6f 6d 2e 6d 79 2f 64 61 74 61 31 2f 69 6d 61 67 65 73 2f 31 32 33 2e 65 78 65 20 2d 4f 75 74 46 69 6c 65 90 0a 37 00 68 74 74 70 73 3a 2f 2f 90 00 } //1
		$a_01_1 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 64 65 6a 78 61 6f 71 65 74 2e 65 78 65 22 } //1 Start-Process -FilePath "C:\Users\Public\Documents\dejxaoqet.exe"
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 } //1 powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass  -command
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}