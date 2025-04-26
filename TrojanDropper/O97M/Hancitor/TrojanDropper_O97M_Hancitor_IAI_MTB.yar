
rule TrojanDropper_O97M_Hancitor_IAI_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 5c 22 20 26 20 22 57 30 22 20 26 20 22 72 64 2e 64 22 20 26 20 22 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 & "\" & "W0" & "rd.d" & "ll") = "" Then
		$a_01_1 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 Set fso = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //1 Set fld = fso.GetFolder(asdf)
		$a_01_3 = {44 69 6d 20 75 75 6a 20 41 73 20 53 74 72 69 6e 67 } //1 Dim uuj As String
		$a_01_4 = {46 75 6e 63 74 69 6f 6e 20 63 68 65 6b 28 29 } //1 Function chek()
		$a_01_5 = {44 69 6d 20 6a 73 61 20 41 73 20 53 74 72 69 6e 67 } //1 Dim jsa As String
		$a_01_6 = {6a 73 61 20 3d 20 57 6f 72 64 2e 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 } //1 jsa = Word.ActiveDocument.AttachedTemplate.Path
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}