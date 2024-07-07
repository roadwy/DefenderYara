
rule TrojanDropper_O97M_Hancitor_IAV_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 22 20 26 20 22 30 22 20 26 20 22 72 22 20 26 20 22 64 2e 64 } //1 W" & "0" & "r" & "d.d
		$a_01_1 = {43 61 6c 6c 20 68 68 68 68 68 } //1 Call hhhhh
		$a_01_2 = {67 6c 6f 70 73 20 3d 20 57 6f 72 64 2e 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 } //1 glops = Word.ActiveDocument.AttachedTemplate.Path
		$a_01_3 = {44 69 6d 20 70 75 73 20 41 73 20 53 74 72 69 6e 67 } //1 Dim pus As String
		$a_01_4 = {66 61 20 3d 20 66 70 73 20 26 20 22 75 22 20 26 20 6a 73 64 20 26 20 22 6c 6c 22 20 26 20 68 68 } //1 fa = fps & "u" & jsd & "ll" & hh
		$a_01_5 = {44 69 6d 20 72 65 67 73 72 76 61 20 41 73 20 4e 65 77 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c } //1 Dim regsrva As New Shell32.Shell
		$a_01_6 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 2c 20 79 79 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 } //1 Call regsrva.ShellExecute(fa, yy, " ", SW_SHOWNORMAL)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}