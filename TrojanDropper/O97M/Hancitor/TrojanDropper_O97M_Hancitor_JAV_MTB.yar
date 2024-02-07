
rule TrojanDropper_O97M_Hancitor_JAV_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 61 22 20 26 20 22 74 69 63 2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c } //01 00  Sta" & "tic.d" & "l" & "l
		$a_01_1 = {2e 70 75 6d 70 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //01 00  .pumpl") = "" Then
		$a_01_2 = {43 61 6c 6c 20 6e 6d 28 6f 6c 6f 6c 6f 77 29 } //01 00  Call nm(ololow)
		$a_01_3 = {43 61 6c 6c 20 72 6e 65 65 28 75 75 75 2c 20 61 61 61 61 29 } //01 00  Call rnee(uuu, aaaa)
		$a_01_4 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //01 00  Set fld = fso.GetFolder(asdf)
		$a_01_5 = {53 75 62 20 72 6e 65 65 28 6d 79 68 6f 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 68 73 61 20 41 73 20 53 74 72 69 6e 67 29 } //00 00  Sub rnee(myhome As String, hsa As String)
	condition:
		any of ($a_*)
 
}