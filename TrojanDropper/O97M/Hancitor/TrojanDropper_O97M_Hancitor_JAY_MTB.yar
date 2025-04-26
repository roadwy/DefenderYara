
rule TrojanDropper_O97M_Hancitor_JAY_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 6a 6f 70 22 2c 20 6d 79 68 6f 6d 65 2c 20 70 6c 6f 70 20 26 20 22 5c 22 20 26 20 22 53 22 20 26 20 22 74 61 22 20 26 20 22 74 69 63 2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c 22 29 } //1 = Application.Run("jop", myhome, plop & "\" & "S" & "ta" & "tic.d" & "l" & "l")
		$a_01_1 = {53 75 62 20 68 68 68 68 68 28 29 } //1 Sub hhhhh()
		$a_01_2 = {44 69 6d 20 70 6f 73 6c 20 41 73 20 53 74 72 69 6e 67 } //1 Dim posl As String
		$a_01_3 = {44 69 6d 20 70 61 66 68 20 41 73 20 53 74 72 69 6e 67 } //1 Dim pafh As String
		$a_01_4 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //1 Set fld = fso.GetFolder(asdf)
		$a_01_5 = {6f 6c 6f 6c 6f 77 } //1 ololow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}