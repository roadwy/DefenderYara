
rule TrojanDropper_O97M_Hancitor_JAT_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 70 75 6d 70 6c 22 20 41 73 20 70 61 66 68 20 26 20 22 5c 22 20 26 20 22 53 74 61 74 69 63 2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c 22 } //01 00  .pumpl" As pafh & "\" & "Static.d" & "l" & "l"
		$a_01_1 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  Set fso = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //01 00  Set fld = fso.GetFolder(asdf)
		$a_01_3 = {46 6f 72 20 45 61 63 68 20 76 68 68 73 20 49 6e 20 66 6c 64 2e 53 55 42 46 4f 4c 44 45 52 53 } //01 00  For Each vhhs In fld.SUBFOLDERS
		$a_01_4 = {28 6f 6c 6f 6c 6f 77 20 41 73 20 53 74 72 69 6e 67 } //01 00  (ololow As String
		$a_01_5 = {44 69 6d 20 6a 6f 73 20 41 73 20 53 74 72 69 6e 67 } //00 00  Dim jos As String
	condition:
		any of ($a_*)
 
}