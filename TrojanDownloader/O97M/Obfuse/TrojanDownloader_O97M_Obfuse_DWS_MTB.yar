
rule TrojanDownloader_O97M_Obfuse_DWS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DWS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 71 77 64 77 71 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set qwdwq = CreateObject("WScript.Shell")
		$a_01_1 = {71 77 64 77 71 2e 52 65 67 57 72 69 74 65 20 64 77 77 71 71 71 71 28 22 } //1 qwdwq.RegWrite dwwqqqq("
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 64 77 77 71 71 71 71 28 73 74 72 29 } //1 Function dwwqqqq(str)
		$a_01_3 = {71 77 64 77 71 2e 52 75 6e 20 28 78 29 } //1 qwdwq.Run (x)
		$a_01_4 = {71 77 64 77 71 2e 52 65 67 44 65 6c 65 74 65 20 64 77 77 71 71 71 71 28 22 } //1 qwdwq.RegDelete dwwqqqq("
		$a_03_5 = {73 53 74 72 20 3d 20 73 53 74 72 20 2b 20 43 68 72 28 43 4c 6e 67 28 22 26 48 22 20 26 20 4d 69 64 28 73 74 72 2c 20 69 2c 20 32 29 29 20 2d 20 33 29 [0-15] 4e 65 78 74 [0-15] 64 77 77 71 71 71 71 20 3d 20 73 53 74 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}