
rule TrojanDropper_O97M_Hancitor_JAX_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 53 22 20 26 20 22 74 61 22 20 26 20 22 74 69 63 2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 & "S" & "ta" & "tic.d" & "l" & "l") = "" Then
		$a_01_1 = {3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 68 69 22 2c 20 52 6f 6f 74 50 61 74 68 29 } //1 = Application.Run("hi", RootPath)
		$a_01_2 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //1 Set fld = fso.GetFolder(asdf)
		$a_01_3 = {66 6c 64 2e 53 55 42 46 4f 4c 44 45 52 53 } //1 fld.SUBFOLDERS
		$a_01_4 = {61 73 64 66 20 3d 20 52 6f 6f 74 50 61 74 68 } //1 asdf = RootPath
		$a_01_5 = {6f 6c 6f 6c 6f 77 } //1 ololow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}