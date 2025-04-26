
rule TrojanDropper_O97M_Powdow_JSE_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.JSE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 61 74 68 20 3d 20 22 63 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 22 20 26 20 45 6d 70 74 79 20 26 20 22 5c 56 69 64 65 6f 73 5c 22 20 26 20 22 74 6a 39 30 22 20 26 20 45 6d 70 74 79 20 26 20 22 2e 6a 22 20 26 20 22 73 65 22 } //1 Path = "c:\Users\Public" & Empty & "\Videos\" & "tj90" & Empty & ".j" & "se"
		$a_01_1 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 4d 65 2e 54 65 78 74 42 6f 78 31 2e 56 61 6c 75 65 20 2b 20 22 20 20 20 20 22 } //1 Print #FileNumber, Me.TextBox1.Value + "    "
		$a_01_2 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 42 75 69 6c 74 69 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 41 75 74 68 6f 72 22 29 20 3d 20 52 65 70 6c 61 63 65 28 22 77 6f 6e 73 63 6f 6e 72 69 70 6f 6e 74 6f 6e 2e 6f 6e 73 68 6f 6e 65 6c 6c 6f 6e 22 2c 20 22 6f 6e 22 2c 20 22 22 29 } //1 ThisWorkbook.BuiltinDocumentProperties("Author") = Replace("wonsconriponton.onshonellon", "on", "")
		$a_01_3 = {6c 6c 20 3d 20 6c 6c 20 26 20 22 2e 72 65 73 74 2f 77 70 2d 22 20 26 20 45 6d 70 74 79 20 26 20 45 6d 70 74 79 20 26 20 22 22 20 26 20 22 69 6e 66 6f 2e 70 22 } //1 ll = ll & ".rest/wp-" & Empty & Empty & "" & "info.p"
		$a_01_4 = {6c 6c 20 3d 20 6c 6c 20 26 20 22 2f 2f 73 68 65 72 70 61 22 } //1 ll = ll & "//sherpa"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}