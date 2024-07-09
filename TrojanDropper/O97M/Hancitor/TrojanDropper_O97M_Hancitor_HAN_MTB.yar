
rule TrojanDropper_O97M_Hancitor_HAN_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //1 Set fld = fso.GetFolder(asdf)
		$a_01_1 = {26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 & "\W0rd.dll") = "" Then
		$a_01_2 = {26 20 22 5c 79 61 2e 77 61 76 22 20 41 73 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22 } //1 & "\ya.wav" As ActiveDocument.AttachedTemplate.Path & "\" & "W0rd.dll"
		$a_01_3 = {26 20 22 5c 79 61 2e 77 61 76 22 20 41 73 20 66 75 } //1 & "\ya.wav" As fu
		$a_01_4 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDropper_O97M_Hancitor_HAN_MTB_2{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 30 72 64 2e 64 6c 6c } //1 W0rd.dll
		$a_01_1 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //1 Set fld = fso.GetFolder(asdf)
		$a_03_2 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 52 6f 6f 74 50 61 74 68 20 26 20 22 5c [0-08] 2e 74 6d 70 22 29 } //1
		$a_01_3 = {49 66 20 73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 22 22 20 54 68 65 6e } //1 If strFileExists = "" Then
		$a_01_4 = {46 75 6e 63 74 69 6f 6e 20 63 68 65 6b 28 29 } //1 Function chek()
		$a_01_5 = {44 69 6d 20 6a 73 61 20 41 73 20 53 74 72 69 6e 67 } //1 Dim jsa As String
		$a_03_6 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 90 0c 02 00 43 61 6c 6c 20 70 6f 6c 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}