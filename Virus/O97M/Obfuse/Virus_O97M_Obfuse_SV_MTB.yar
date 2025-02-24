
rule Virus_O97M_Obfuse_SV_MTB{
	meta:
		description = "Virus:O97M/Obfuse.SV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 74 72 45 6e 67 69 6e 65 20 3d 20 55 43 61 73 65 24 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 2b 20 22 5c 22 20 2b 20 63 73 74 72 45 6e 67 69 6e 65 29 } //1 strEngine = UCase$(Application.StartupPath + "\" + cstrEngine)
		$a_01_1 = {49 66 20 4c 65 6e 28 44 69 72 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 29 20 3d 20 30 20 54 68 65 6e 20 4d 6b 44 69 72 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 } //1 If Len(Dir(Application.StartupPath, vbDirectory)) = 0 Then MkDir Application.StartupPath
		$a_01_2 = {47 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 20 4c 65 66 74 24 28 73 74 72 45 6e 67 69 6e 65 2c 20 49 6e 53 74 72 28 31 2c 20 73 74 72 45 6e 67 69 6e 65 2c 20 22 5c 22 29 29 2c 20 30 2c 20 30 2c 20 6c 6e 67 56 6f 6c 75 6d 65 49 44 2c 20 30 2c 20 30 2c 20 30 2c 20 30 } //1 GetVolumeInformation Left$(strEngine, InStr(1, strEngine, "\")), 0, 0, lngVolumeID, 0, 0, 0, 0
		$a_01_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 63 72 65 65 6e 55 70 64 61 74 69 6e 67 20 3d 20 54 72 75 65 } //1 Application.ScreenUpdating = True
		$a_01_4 = {63 6d 64 54 61 72 67 65 74 2e 44 65 6c 65 74 65 4c 69 6e 65 73 20 31 2c 20 63 6d 64 53 6f 75 72 63 65 2e 43 6f 75 6e 74 4f 66 4c 69 6e 65 73 } //1 cmdTarget.DeleteLines 1, cmdSource.CountOfLines
		$a_01_5 = {77 62 6b 54 61 72 67 65 74 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 70 70 74 56 6f 6c 75 6d 65 2e 4e 61 6d 65 29 2e 56 61 6c 75 65 20 3d 20 70 70 74 56 6f 6c 75 6d 65 2e 56 61 6c 75 65 } //1 wbkTarget.CustomDocumentProperties(pptVolume.Name).Value = pptVolume.Value
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}