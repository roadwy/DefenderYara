
rule TrojanDropper_O97M_GraceWire_CW_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 52 50 20 3d 20 22 25 22 20 26 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 PRP = "%" & Dialog4.TextBox1.Tag
		$a_01_1 = {44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 3d 20 72 65 64 6f 4d 6f 63 68 75 70 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 50 52 50 20 2b 20 22 25 22 29 } //1 Dialog4.TextBox1.Tag = redoMochup.ExpandEnvironmentStrings(PRP + "%")
		$a_01_2 = {44 69 6d 20 63 61 72 20 41 73 20 52 65 70 6f 73 69 74 6f 72 } //1 Dim car As Repositor
		$a_01_3 = {44 69 6d 20 53 70 65 63 69 61 6c 50 61 74 68 20 41 73 20 53 74 72 69 6e 67 } //1 Dim SpecialPath As String
		$a_01_4 = {50 75 62 6c 69 63 20 53 75 62 20 57 75 7a 7a 79 42 75 64 } //1 Public Sub WuzzyBud
		$a_01_5 = {73 20 3d 20 22 4d 61 6a 6f 72 20 68 65 61 6c 74 68 20 70 72 6f 62 6c 65 6d 73 22 } //1 s = "Major health problems"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}