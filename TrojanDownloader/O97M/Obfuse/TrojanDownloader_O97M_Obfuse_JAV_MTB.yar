
rule TrojanDownloader_O97M_Obfuse_JAV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 61 74 68 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 29 20 3d 20 22 22 } //1 Path & "\W0rd.dll") = ""
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 20 26 20 22 6e 64 22 20 26 20 22 6c 6c 22 20 26 20 22 33 32 2e 65 78 65 } //1 ShellExecute(fa & "nd" & "ll" & "32.exe
		$a_01_2 = {57 30 72 64 2e 64 6c 6c 2c 53 74 61 72 74 22 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c } //1 W0rd.dll,Start", " ", SW_SHOWNORMAL
		$a_01_3 = {79 61 2e 77 61 76 22 20 41 73 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 } //1 ya.wav" As ActiveDocument.AttachedTemplate.Path & "\W0rd.dll"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}