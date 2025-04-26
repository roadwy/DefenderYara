
rule TrojanDropper_O97M_Hancitor_HAO_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 30 72 64 2e 64 6c 6c } //1 W0rd.dll
		$a_01_1 = {26 20 6a 73 64 20 26 } //1 & jsd &
		$a_01_2 = {49 66 20 44 69 72 28 6e 6f 74 68 69 6e 67 73 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(nothings & "\" & "W0rd.dll") = "" Then
		$a_01_3 = {26 20 22 6d 70 22 20 41 73 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22 } //1 & "mp" As ActiveDocument.AttachedTemplate.Path & "\" & "W0rd.dll"
		$a_03_4 = {53 75 62 20 73 73 73 73 28 29 90 0c 02 00 44 69 6d 20 70 6f 73 6c 20 41 73 20 53 74 72 69 6e 67 } //1
		$a_01_5 = {43 61 6c 6c 20 67 6f 74 6f 64 6f 77 6e } //1 Call gotodown
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}