
rule TrojanDropper_O97M_GraceWire_CQ_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 52 50 20 3d 20 22 25 22 20 26 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //01 00  PRP = "%" & Dialog4.TextBox1.Tag
		$a_01_1 = {50 75 62 6c 69 63 20 53 75 62 20 57 75 7a 7a 79 42 75 64 28 64 49 6d 6d 65 72 20 41 73 20 49 6e 74 65 67 65 72 29 } //01 00  Public Sub WuzzyBud(dImmer As Integer)
		$a_01_2 = {44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 3d 20 72 65 64 6f 4d 6f 63 68 75 70 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 50 52 50 20 2b 20 22 25 22 29 } //01 00  Dialog4.TextBox1.Tag = redoMochup.ExpandEnvironmentStrings(PRP + "%")
		$a_01_3 = {73 20 3d 20 22 4e 6f 20 68 65 61 6c 74 68 20 70 72 6f 62 6c 65 6d 73 22 } //00 00  s = "No health problems"
	condition:
		any of ($a_*)
 
}