
rule TrojanDownloader_O97M_Donoff_EML{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EML,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 2e 64 6c 6c 22 } //3 Private Declare Function URLDownloadToFileW Lib "urlmon.dll"
		$a_01_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 53 68 65 6c 6c 45 78 65 63 75 74 65 57 20 4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 } //3 Private Declare Function ShellExecuteW Lib "shell32.dll"
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 44 69 73 70 6c 61 79 41 6c 65 72 74 73 20 3d 20 46 61 6c 73 65 } //2 Application.DisplayAlerts = False
		$a_03_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 22 [0-ff] 2e 65 78 65 22 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_03_3  & 1)*1) >=9
 
}