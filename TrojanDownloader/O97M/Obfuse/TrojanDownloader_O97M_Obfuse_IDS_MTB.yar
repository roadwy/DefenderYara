
rule TrojanDownloader_O97M_Obfuse_IDS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IDS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 69 6d 20 61 57 73 36 47 20 41 73 20 4e 65 77 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c } //1 Dim aWs6G As New Shell32.Shell
		$a_01_1 = {61 57 73 36 47 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 61 7a 41 49 62 48 2c 20 61 48 62 50 30 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c } //1 aWs6G.ShellExecute azAIbH, aHbP0, " ", SW_SHOWNORMAL
		$a_01_2 = {61 77 45 33 53 20 3d 20 53 70 6c 69 74 28 61 71 47 6d 6e 2c 20 43 68 72 28 } //1 awE3S = Split(aqGmn, Chr(
		$a_01_3 = {61 51 4e 70 63 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 } //1 aQNpc = ActiveDocument.Content
		$a_01_4 = {50 72 69 6e 74 20 23 31 2c 20 61 38 50 4e 30 } //1 Print #1, a8PN0
		$a_01_5 = {61 74 31 55 50 20 3d 20 61 67 65 75 30 6f 28 61 58 4c 42 41 28 61 55 30 43 6d 77 29 20 58 6f 72 } //1 at1UP = ageu0o(aXLBA(aU0Cmw) Xor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}