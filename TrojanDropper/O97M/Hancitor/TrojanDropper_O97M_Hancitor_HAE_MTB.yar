
rule TrojanDropper_O97M_Hancitor_HAE_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6c 6f 67 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 } //01 00  glog = ActiveDocument.AttachedTemplate.Path
		$a_01_1 = {44 69 6d 20 66 75 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim fu As String
		$a_01_2 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //01 00  Set fld = fso.GetFolder(asdf)
		$a_01_3 = {66 75 20 3d 20 67 6c 6f 67 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 } //01 00  fu = glog & "\W0rd.dll"
		$a_03_4 = {4e 61 6d 65 20 6d 79 68 6f 6d 65 20 26 20 22 5c 79 61 2e 77 61 76 22 20 41 73 20 66 75 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_5 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 2c 20 79 79 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 } //00 00  Call regsrva.ShellExecute(fa, yy, " ", SW_SHOWNORMAL)
	condition:
		any of ($a_*)
 
}