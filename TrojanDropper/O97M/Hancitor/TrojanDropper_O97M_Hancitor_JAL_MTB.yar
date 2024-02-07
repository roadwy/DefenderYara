
rule TrojanDropper_O97M_Hancitor_JAL_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 63 68 65 6b 28 29 } //01 00  Function chek()
		$a_01_1 = {44 69 6d 20 6a 6f 73 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim jos As String
		$a_01_2 = {6a 6f 73 20 3d 20 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 54 65 6d 70 46 69 6c 65 50 61 74 68 29 } //01 00  jos = Options.DefaultFilePath(wdTempFilePath)
		$a_01_3 = {49 66 20 44 69 72 28 6a 6f 73 20 26 20 22 5c 53 74 61 74 69 63 2e 64 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //01 00  If Dir(jos & "\Static.dll") = "" Then
		$a_01_4 = {63 68 65 6b 20 3d 20 30 } //01 00  chek = 0
		$a_01_5 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //01 00  Set fld = fso.GetFolder(asdf)
		$a_01_6 = {43 61 6c 6c 20 63 68 65 63 6b 74 68 65 28 61 66 73 29 } //00 00  Call checkthe(afs)
	condition:
		any of ($a_*)
 
}