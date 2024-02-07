
rule TrojanDropper_O97M_Hancitor_IAN_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 66 20 44 69 72 28 6a 73 61 20 26 20 22 5c 22 20 26 20 22 57 30 22 20 26 20 22 72 64 2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //01 00  If Dir(jsa & "\" & "W0" & "rd.d" & "l" & "l") = "" Then
		$a_01_1 = {44 69 6d 20 66 65 72 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim fer As String
		$a_01_2 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  Set fso = CreateObject("Scripting.FileSystemObject")
		$a_01_3 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //01 00  Set fld = fso.GetFolder(asdf)
		$a_01_4 = {44 69 6d 20 75 75 6a 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim uuj As String
		$a_03_5 = {75 75 6a 20 3d 20 22 5c 22 20 26 20 22 90 02 10 2e 74 22 20 26 20 22 6d 70 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}