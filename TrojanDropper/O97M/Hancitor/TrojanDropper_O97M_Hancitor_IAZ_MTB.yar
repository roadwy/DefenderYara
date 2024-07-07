
rule TrojanDropper_O97M_Hancitor_IAZ_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 6d 22 20 26 20 22 70 22 20 41 73 20 57 6f 72 64 2e 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 53 74 61 74 69 63 2e 64 6c 6c 22 } //1 & "m" & "p" As Word.ActiveDocument.AttachedTemplate.Path & "\Static.dll"
		$a_01_1 = {70 6f 73 6c 20 3d 20 57 6f 72 64 2e 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 } //1 posl = Word.ActiveDocument.AttachedTemplate.Path
		$a_01_2 = {43 61 6c 6c 20 47 65 74 6d 65 28 4c 65 66 74 28 6b 6c 61 73 2c 20 6e 74 67 73 29 20 26 20 79 65 72 29 } //1 Call Getme(Left(klas, ntgs) & yer)
		$a_01_3 = {53 75 62 20 68 68 68 68 68 28 29 } //1 Sub hhhhh()
		$a_01_4 = {44 69 6d 20 70 6f 73 6c 20 41 73 20 53 74 72 69 6e 67 } //1 Dim posl As String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}