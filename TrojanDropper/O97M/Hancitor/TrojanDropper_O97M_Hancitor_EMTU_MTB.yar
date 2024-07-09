
rule TrojanDropper_O97M_Hancitor_EMTU_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EMTU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 5c 65 64 67 65 2e 64 22 } //1 = "\edge.d"
		$a_01_1 = {44 69 6d 20 6a 73 64 20 41 73 20 53 74 72 69 6e 67 } //1 Dim jsd As String
		$a_01_2 = {44 69 6d 20 70 75 73 20 41 73 20 53 74 72 69 6e 67 } //1 Dim pus As String
		$a_03_3 = {2e 52 75 6e 20 66 61 20 26 20 22 20 22 20 26 20 79 79 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65 2c 20 77 61 69 74 4f 6e 52 65 74 75 72 6e 90 0c 02 00 45 6e 64 20 49 66 90 0c 02 00 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDropper_O97M_Hancitor_EMTU_MTB_2{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EMTU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 44 69 72 28 6a 6f 73 20 26 20 22 5c 65 64 67 65 2e 64 22 20 26 20 22 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(jos & "\edge.d" & "ll") = "" Then
		$a_01_1 = {53 65 74 20 78 63 76 78 76 20 3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set xcvxv = VBA.CreateObject("WScript.Shell")
		$a_01_2 = {78 63 76 78 76 2e 52 75 6e 20 62 63 76 73 64 73 66 20 26 20 22 20 22 20 26 20 6f 79 73 } //1 xcvxv.Run bcvsdsf & " " & oys
		$a_01_3 = {43 61 6c 6c 20 71 31 28 6b 66 29 } //1 Call q1(kf)
		$a_01_4 = {44 69 6d 20 70 61 66 68 20 41 73 20 53 74 72 69 6e 67 } //1 Dim pafh As String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}