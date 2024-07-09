
rule TrojanDownloader_O97M_Powdow_RSF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RSF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {77 77 77 31 31 36 2e 7a 69 70 70 79 73 68 61 72 65 2e 63 6f 6d 2f 64 2f 33 73 57 71 68 6b 33 51 2f 32 36 39 2f 74 65 73 74 2e 70 73 31 90 0a 3d 00 24 77 65 62 20 3d 20 27 68 74 74 70 73 3a 2f 2f } //1
		$a_01_1 = {66 73 6f 31 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 72 75 6e 2e 62 61 74 22 2c 20 54 72 75 65 29 } //1 fso1.CreateTextFile("c:\run.bat", True)
		$a_01_2 = {73 68 65 6c 6c 2e 52 75 6e 20 22 72 75 6e 22 } //1 shell.Run "run"
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_01_4 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}