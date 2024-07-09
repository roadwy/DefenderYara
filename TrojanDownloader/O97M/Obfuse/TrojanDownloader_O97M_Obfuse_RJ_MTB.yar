
rule TrojanDownloader_O97M_Obfuse_RJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 70 65 63 69 61 6c 50 61 74 68 20 3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 54 65 6d 70 6c 61 74 65 73 22 29 } //1 SpecialPath = WshShell.SpecialFolders("Templates")
		$a_01_1 = {44 69 6d 20 57 73 68 53 68 65 6c 6c 20 41 73 20 4f 62 6a 65 63 74 } //1 Dim WshShell As Object
		$a_01_2 = {3d 20 43 68 72 28 35 30 29 20 2b 20 43 68 72 28 34 38 29 20 2b 20 43 68 72 28 34 38 29 } //1 = Chr(50) + Chr(48) + Chr(48)
		$a_01_3 = {2e 53 74 61 74 75 73 20 3d 20 32 30 30 20 54 68 65 6e } //1 .Status = 200 Then
		$a_01_4 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c } //1 .Open "get",
		$a_01_5 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 4c 65 6e 28 } //1 For i = 1 To Len(
		$a_03_6 = {2e 43 6c 6f 73 65 90 0c 02 00 45 6e 64 20 49 66 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}