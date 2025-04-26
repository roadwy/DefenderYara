
rule TrojanDropper_O97M_Hancitor_HAC_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 } //1 Sub gotodown()
		$a_01_1 = {43 61 6c 6c 20 67 6f 74 6f 74 77 6f } //1 Call gototwo
		$a_03_2 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 [0-08] 20 26 20 22 5c 79 61 2e 77 61 76 22 29 } //1
		$a_01_3 = {49 66 20 44 69 72 28 6e 6f 74 68 69 6e 67 73 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(nothings & "\" & "W0rd.dll") = "" Then
		$a_01_4 = {26 20 22 5c 79 61 2e 77 61 76 22 20 41 73 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22 } //1 & "\ya.wav" As ActiveDocument.AttachedTemplate.Path & "\" & "W0rd.dll"
		$a_01_5 = {49 66 20 73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 22 22 20 54 68 65 6e } //1 If strFileExists = "" Then
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}