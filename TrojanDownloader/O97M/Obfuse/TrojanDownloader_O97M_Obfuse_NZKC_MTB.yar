
rule TrojanDownloader_O97M_Obfuse_NZKC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NZKC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 20 26 20 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 53 74 61 72 74 75 70 50 61 74 68 29 20 26 20 22 5c 7a 73 2e 7a 2c 58 42 44 4f 41 4f 55 46 4d 52 48 22 29 } //1 Shell ("rundll32.exe " & Options.DefaultFilePath(wdStartupPath) & "\zs.z,XBDOAOUFMRH")
		$a_01_1 = {53 65 74 20 46 53 4f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 Set FSO = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {53 65 61 72 63 68 20 46 53 4f 2e 47 65 74 46 6f 6c 64 65 72 28 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 54 65 6d 70 46 69 6c 65 50 61 74 68 29 29 } //1 Search FSO.GetFolder(Options.DefaultFilePath(wdTempFilePath))
		$a_01_3 = {49 66 20 46 69 6c 2e 4e 61 6d 65 20 3d 20 22 66 61 78 2e 66 22 20 54 68 65 6e } //1 If Fil.Name = "fax.f" Then
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}