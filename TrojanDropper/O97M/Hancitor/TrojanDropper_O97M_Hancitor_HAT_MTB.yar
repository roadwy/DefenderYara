
rule TrojanDropper_O97M_Hancitor_HAT_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 30 72 64 2e 64 6c 6c } //1 W0rd.dll
		$a_01_1 = {61 73 64 66 20 3d 20 52 6f 6f 74 50 61 74 68 } //1 asdf = RootPath
		$a_01_2 = {44 69 6d 20 66 65 72 20 41 73 20 53 74 72 69 6e 67 } //1 Dim fer As String
		$a_01_3 = {44 69 6d 20 6a 73 61 20 41 73 20 53 74 72 69 6e 67 } //1 Dim jsa As String
		$a_01_4 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 Set fso = CreateObject("Scripting.FileSystemObject")
		$a_01_5 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //1 Set fld = fso.GetFolder(asdf)
		$a_03_6 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 52 6f 6f 74 50 61 74 68 20 26 20 22 5c 90 02 10 2e 74 22 20 26 20 22 6d 70 22 29 90 00 } //1
		$a_01_7 = {49 66 20 73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 22 22 20 54 68 65 6e } //1 If strFileExists = "" Then
		$a_01_8 = {46 6f 72 20 45 61 63 68 20 76 68 68 73 20 49 6e 20 66 6c 64 2e 53 55 42 46 4f 4c 44 45 52 53 } //1 For Each vhhs In fld.SUBFOLDERS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}