
rule TrojanDownloader_O97M_Obfuse_IL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 [0-09] 28 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-09] 2e 78 73 6c 22 2c 20 [0-09] 28 [0-09] 28 31 29 29 29 } //1
		$a_03_1 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-09] 2c 20 [0-09] 2c 20 32 29 29 29 } //1
		$a_01_2 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //1 = New WshShell
		$a_03_3 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-09] 29 20 53 74 65 70 20 32 } //1
		$a_01_4 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 63 63 65 70 74 41 6c 6c 52 65 76 69 73 69 6f 6e 73 53 68 6f 77 6e } //1 ActiveDocument.AcceptAllRevisionsShown
		$a_01_5 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 } //1 ActiveDocument.Bookmarks
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}