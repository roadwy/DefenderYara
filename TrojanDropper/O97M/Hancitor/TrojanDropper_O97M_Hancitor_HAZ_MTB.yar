
rule TrojanDropper_O97M_Hancitor_HAZ_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 30 72 64 2e 64 6c 6c } //1 W0rd.dll
		$a_01_1 = {26 20 6a 73 64 20 26 } //1 & jsd &
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 63 68 65 6b 28 29 } //1 Function chek()
		$a_01_3 = {44 69 6d 20 6a 73 61 20 41 73 20 53 74 72 69 6e 67 } //1 Dim jsa As String
		$a_01_4 = {53 75 62 20 68 68 68 68 68 28 29 } //1 Sub hhhhh()
		$a_01_5 = {44 69 6d 20 70 6f 73 6c 20 41 73 20 53 74 72 69 6e 67 } //1 Dim posl As String
		$a_01_6 = {41 73 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22 } //1 As ActiveDocument.Application.StartupPath & "\" & "W0rd.dll"
		$a_01_7 = {26 20 70 75 73 68 73 74 72 20 26 20 22 6c 6c 22 20 26 } //1 & pushstr & "ll" &
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}