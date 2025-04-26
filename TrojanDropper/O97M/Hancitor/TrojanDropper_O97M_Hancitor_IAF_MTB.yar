
rule TrojanDropper_O97M_Hancitor_IAF_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 5c 22 20 26 20 22 57 30 22 20 26 20 22 72 64 2e 64 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 & "\" & "W0" & "rd.dll") = "" Then
		$a_01_1 = {43 61 6c 6c 20 68 68 68 68 68 } //1 Call hhhhh
		$a_01_2 = {44 69 6d 20 70 75 73 68 73 74 72 20 41 73 20 53 74 72 69 6e 67 } //1 Dim pushstr As String
		$a_01_3 = {70 75 73 68 73 74 72 20 3d 20 22 5c 57 22 20 26 20 22 30 72 22 20 26 20 22 64 2e 64 } //1 pushstr = "\W" & "0r" & "d.d
		$a_01_4 = {44 69 6d 20 6a 73 64 20 41 73 20 53 74 72 69 6e 67 } //1 Dim jsd As String
		$a_01_5 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 } //1 Call regsrva.ShellExecute(
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}