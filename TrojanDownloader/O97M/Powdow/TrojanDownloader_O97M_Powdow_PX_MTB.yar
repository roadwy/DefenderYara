
rule TrojanDownloader_O97M_Powdow_PX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //1 powershell.exe -WindowStyle Hidden
		$a_02_1 = {68 74 74 70 3a 2f 2f 33 35 2e 31 37 38 2e 37 35 2e 36 39 2f 38 2f 90 02 0a 2e 6a 70 67 90 00 } //1
		$a_00_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 } //1 Start-Process -FilePath
		$a_02_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 56 69 64 65 6f 73 5c 90 02 0a 2e 65 78 65 90 00 } //1
		$a_00_4 = {77 69 6e 6d 67 6d 74 73 3a 77 69 6e 33 32 5f 50 72 6f 63 65 73 73 } //1 winmgmts:win32_Process
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}