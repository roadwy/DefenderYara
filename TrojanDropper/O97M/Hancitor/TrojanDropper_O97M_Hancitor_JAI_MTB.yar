
rule TrojanDropper_O97M_Hancitor_JAI_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {22 5c 53 74 61 74 69 63 2e 64 22 } //1 "\Static.d"
		$a_01_1 = {43 61 6c 6c 20 73 74 65 74 70 74 77 77 6f } //1 Call stetptwwo
		$a_01_2 = {43 61 6c 6c 20 68 68 68 68 68 } //1 Call hhhhh
		$a_01_3 = {66 61 20 3d 20 66 70 73 20 26 20 22 75 22 20 26 20 6a 73 64 20 26 20 22 6c 6c 22 20 26 20 68 68 } //1 fa = fps & "u" & jsd & "ll" & hh
		$a_01_4 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 2c 20 79 79 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 } //1 Call regsrva.ShellExecute(fa, yy, " ", SW_SHOWNORMAL)
		$a_01_5 = {44 69 6d 20 72 65 67 73 72 76 61 20 41 73 20 4e 65 77 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c } //1 Dim regsrva As New Shell32.Shell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}