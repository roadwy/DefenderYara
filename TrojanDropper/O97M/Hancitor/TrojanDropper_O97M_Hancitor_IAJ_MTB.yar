
rule TrojanDropper_O97M_Hancitor_IAJ_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 30 22 20 26 20 22 72 64 2e 64 22 20 26 20 22 6c 6c } //1 W0" & "rd.d" & "ll
		$a_01_1 = {53 75 62 20 68 68 68 68 68 28 29 } //1 Sub hhhhh()
		$a_01_2 = {44 69 6d 20 70 6f 73 6c 20 41 73 20 53 74 72 69 6e 67 } //1 Dim posl As String
		$a_01_3 = {70 6f 73 6c 20 3d 20 57 6f 72 64 2e 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 } //1 posl = Word.ActiveDocument.AttachedTemplate.Path
		$a_01_4 = {44 69 6d 20 6e 74 67 73 } //1 Dim ntgs
		$a_01_5 = {44 69 6d 20 73 64 61 } //1 Dim sda
		$a_01_6 = {43 61 6c 6c 20 66 6b 65 } //1 Call fke
		$a_01_7 = {79 65 72 20 3d 20 22 4c 6f 63 22 20 26 20 22 61 6c 22 20 26 20 22 5c 54 65 22 20 26 20 22 6d 70 22 } //1 yer = "Loc" & "al" & "\Te" & "mp"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}