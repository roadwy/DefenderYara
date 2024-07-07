
rule TrojanDownloader_O97M_Obfuse_RW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 70 65 63 69 61 6c 50 61 74 68 20 3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 54 65 6d 70 6c 61 74 65 73 22 29 } //1 SpecialPath = WshShell.SpecialFolders("Templates")
		$a_01_1 = {44 69 6d 20 57 73 68 53 68 65 6c 6c 20 41 73 20 4f 62 6a 65 63 74 } //1 Dim WshShell As Object
		$a_01_2 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c } //1 .Open "get",
		$a_01_3 = {2e 53 74 61 74 75 73 20 3d 20 32 30 30 20 54 68 65 6e } //1 .Status = 200 Then
		$a_01_4 = {2e 73 65 6e 64 } //1 .send
		$a_03_5 = {72 65 76 65 72 73 65 64 54 65 78 74 20 3d 20 72 65 76 65 72 73 65 64 54 65 78 74 20 26 20 4d 69 64 28 74 65 78 74 2c 20 28 6c 65 6e 67 74 68 20 2d 20 69 29 2c 20 31 29 90 02 20 4e 65 78 74 20 69 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}