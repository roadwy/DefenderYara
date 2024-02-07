
rule TrojanDropper_O97M_Hancitor_JAB_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 61 74 69 63 2e 64 } //01 00  Static.d
		$a_01_1 = {43 61 6c 6c 20 68 68 68 68 68 } //01 00  Call hhhhh
		$a_01_2 = {43 61 6c 6c 20 73 74 65 74 70 74 77 77 6f } //01 00  Call stetptwwo
		$a_01_3 = {66 61 20 3d 20 66 70 73 20 26 20 22 75 22 20 26 20 6a 73 64 20 26 20 22 6c 6c 22 20 26 20 68 68 } //01 00  fa = fps & "u" & jsd & "ll" & hh
		$a_01_4 = {44 69 6d 20 72 65 67 73 72 76 61 20 41 73 20 4e 65 77 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c } //01 00  Dim regsrva As New Shell32.Shell
		$a_01_5 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 2c 20 79 79 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 } //01 00  Call regsrva.ShellExecute(fa, yy, " ", SW_SHOWNORMAL)
		$a_01_6 = {67 6c 6f 70 73 20 3d 20 57 6f 72 64 2e 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 } //00 00  glops = Word.ActiveDocument.AttachedTemplate.Path
	condition:
		any of ($a_*)
 
}