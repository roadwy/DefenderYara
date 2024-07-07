
rule TrojanDropper_O97M_Hancitor_IAL_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {44 69 6d 20 6f 6c 6f 6c 6f 77 20 41 73 20 53 74 72 69 6e 67 } //1 Dim ololow As String
		$a_01_1 = {6f 6c 6f 6c 6f 77 20 3d 20 73 66 } //1 ololow = sf
		$a_01_2 = {44 69 6d 20 6e 6f 74 68 69 6e 67 73 20 41 73 20 53 74 72 69 6e 67 } //1 Dim nothings As String
		$a_01_3 = {6e 6f 74 68 69 6e 67 73 20 3d 20 70 61 66 68 20 26 20 22 5c 22 20 26 20 22 57 30 22 20 26 20 22 72 64 2e 64 22 20 26 20 22 6c 6c 22 } //1 nothings = pafh & "\" & "W0" & "rd.d" & "ll"
		$a_03_4 = {49 66 20 44 69 72 28 73 66 20 26 20 22 5c 90 02 10 2e 74 22 20 26 20 22 6d 70 22 29 20 3d 20 22 22 20 54 68 65 6e 90 00 } //1
		$a_01_5 = {53 75 62 20 63 68 65 63 6b 74 68 65 28 73 66 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub checkthe(sf As String)
		$a_01_6 = {43 61 6c 6c 20 6e 6d 28 6f 6c 6f 6c 6f 77 29 } //1 Call nm(ololow)
		$a_01_7 = {26 20 6a 73 64 20 26 } //1 & jsd &
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}