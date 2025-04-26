
rule TrojanDropper_O97M_Hancitor_EOAX_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 53 65 61 72 63 68 28 4d 79 46 53 4f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 61 29 2c 20 68 64 76 29 } //1 Call Search(MyFSO.GetFolder(asda), hdv)
		$a_01_1 = {43 61 6c 6c 20 70 70 70 78 28 76 63 62 63 20 26 20 22 5c 67 6c 69 62 2e 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 29 } //1 Call pppx(vcbc & "\glib.d" & "o" & "c")
		$a_01_2 = {49 66 20 44 69 72 28 76 63 62 63 20 26 20 22 5c 67 6c 69 62 2e 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(vcbc & "\glib.d" & "o" & "c") = "" Then
		$a_01_3 = {44 69 6d 20 64 66 67 64 67 64 67 } //1 Dim dfgdgdg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}