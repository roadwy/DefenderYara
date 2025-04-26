
rule TrojanDownloader_O97M_Obfuse_EG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set WshShell = CreateObject("WScript.Shell")
		$a_00_1 = {53 70 65 63 69 61 6c 50 61 74 68 20 3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 54 65 6d 70 6c 61 74 65 73 22 29 } //1 SpecialPath = WshShell.SpecialFolders("Templates")
		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Shell.Application")
		$a_00_3 = {3d 20 53 70 65 63 69 61 6c 50 61 74 68 20 2b 20 44 65 63 72 79 70 74 28 } //1 = SpecialPath + Decrypt(
		$a_00_4 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 44 65 63 72 79 70 74 28 22 71 } //1 .Open "get", Decrypt("q
		$a_00_5 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 7a 65 62 72 61 73 63 64 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 74 75 76 77 78 79 } //1 As String = "zebrascdfghijklmnopqtuvwxy
		$a_00_6 = {44 65 63 72 79 70 74 20 3d 20 44 65 63 72 79 70 74 20 26 20 4d 69 64 28 } //1 Decrypt = Decrypt & Mid(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}