
rule TrojanDownloader_O97M_Obfuse_PHM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PHM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {22 73 74 61 72 74 20 2f 4d 49 4e 20 43 3a 5c 57 69 6e 64 6f 22 } //1 "start /MIN C:\Windo"
		$a_01_1 = {22 77 73 5c 53 79 73 74 65 6d 33 32 5c 22 20 2b 20 22 57 69 6e 64 6f 77 73 50 6f 22 20 2b 20 22 77 65 72 53 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 22 20 2b 20 22 65 72 73 68 65 6c 6c 2e 65 78 65 22 } //1 "ws\System32\" + "WindowsPo" + "werShell\v1.0\pow" + "ershell.exe"
		$a_01_2 = {22 20 2d 77 69 6e 20 31 20 2d 65 6e 63 22 } //1 " -win 1 -enc"
		$a_01_3 = {53 68 65 6c 6c 28 62 61 74 63 68 2c 20 30 29 } //1 Shell(batch, 0)
		$a_01_4 = {4a 41 42 51 41 48 49 41 62 77 42 6a 41 45 } //1 JABQAHIAbwBjAE
		$a_03_5 = {62 61 74 63 68 20 3d 20 22 90 02 19 2e 62 61 74 22 90 00 } //1
		$a_01_6 = {42 6c 41 47 34 41 64 67 41 36 41 45 45 41 55 } //1 BlAG4AdgA6AEEAU
		$a_01_7 = {51 41 45 51 41 51 51 42 55 41 45 45 41 } //1 QAEQAQQBUAEEA
		$a_01_8 = {41 41 63 67 42 76 41 47 4d 41 } //1 AAcgBvAGMA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}