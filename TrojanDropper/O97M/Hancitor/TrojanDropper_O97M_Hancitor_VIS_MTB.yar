
rule TrojanDropper_O97M_Hancitor_VIS_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 22 20 26 20 22 64 6c 22 } //1 run" & "dl"
		$a_01_1 = {41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c 20 68 77 6e 64 20 41 73 20 4c 6f 6e 67 2c 20 5f } //1 Alias "ShellExecuteA" (ByVal hwnd As Long, _
		$a_01_2 = {4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 } //1 Option Explicit
		$a_01_3 = {49 66 20 44 69 72 28 76 63 62 63 20 26 20 22 5c 6b 69 6b 75 73 2e 64 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(vcbc & "\kikus.dll") = "" Then
		$a_03_4 = {76 63 62 63 20 26 20 22 5c 6b 69 6b 75 73 2e 64 6c 6c 2c 90 02 0f 22 2c 20 5f 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}