
rule TrojanDownloader_O97M_Donoff_RBS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 [0-13] 2e 76 62 73 22 } //1
		$a_03_1 = {77 77 77 2e 77 68 65 72 65 76 65 72 2e 63 6f 6d 2f 66 69 6c 65 73 2f 70 61 79 6c 6f 61 64 2e 65 78 65 22 2c 20 22 43 3a 5c 74 65 6d 70 22 90 0a 43 00 48 54 54 50 44 6f 77 6e 6c 6f 61 64 20 22 68 74 74 70 3a 2f 2f } //1
		$a_01_2 = {57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 WScript.CreateObject("WScript.Shell")
		$a_01_3 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 22 63 3a 5c 74 65 6d 70 5c 70 61 79 6c 6f 61 64 2e 65 78 65 22 } //1 WshShell.Run "c:\temp\payload.exe"
		$a_01_4 = {43 68 72 28 41 73 63 42 28 4d 69 64 42 28 6f 62 6a 48 54 54 50 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 2c 20 69 2c 20 31 29 } //1 Chr(AscB(MidB(objHTTP.ResponseBody, i, 1)
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}