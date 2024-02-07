
rule TrojanDropper_O97M_Hancitor_IAH_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 61 20 3d 20 66 70 73 20 26 20 22 75 22 20 26 20 6a 73 64 20 26 20 22 6c 6c 22 20 26 20 68 68 } //01 00  fa = fps & "u" & jsd & "ll" & hh
		$a_01_1 = {44 69 6d 20 72 65 67 73 72 76 61 20 41 73 20 4e 65 77 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c } //01 00  Dim regsrva As New Shell32.Shell
		$a_01_2 = {26 20 79 79 20 26 20 70 75 73 68 73 74 72 20 26 20 22 6c 6c 22 20 26 20 22 2c 55 6d 69 6e 73 6c 61 49 49 46 30 6d 74 22 } //01 00  & yy & pushstr & "ll" & ",UminslaIIF0mt"
		$a_01_3 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 2c 20 79 79 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 } //01 00  Call regsrva.ShellExecute(fa, yy, " ", SW_SHOWNORMAL)
		$a_01_4 = {43 61 6c 6c 20 68 68 68 68 68 } //01 00  Call hhhhh
		$a_01_5 = {44 69 6d 20 70 75 73 68 73 74 72 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim pushstr As String
		$a_01_6 = {70 75 73 68 73 74 72 20 3d 20 22 5c 57 22 20 26 20 22 30 72 22 20 26 20 22 64 2e 64 22 } //00 00  pushstr = "\W" & "0r" & "d.d"
	condition:
		any of ($a_*)
 
}