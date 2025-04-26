
rule TrojanDropper_O97M_Hancitor_JAD_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 74 69 63 2e 64 6c 6c } //1 Static.dll
		$a_01_1 = {53 75 62 20 63 68 65 63 6b 74 68 65 28 73 66 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub checkthe(sf As String)
		$a_03_2 = {49 66 20 44 69 72 28 73 66 20 26 20 22 5c [0-12] 2e 74 30 22 20 26 20 22 6d 70 22 29 20 3d 20 22 22 20 54 68 65 6e } //1
		$a_01_3 = {70 61 66 68 20 3d 20 69 65 70 } //1 pafh = iep
		$a_01_4 = {43 61 6c 6c 20 6e 6d 28 6f 6c 6f 6c 6f 77 29 } //1 Call nm(ololow)
		$a_01_5 = {6f 6c 6f 6c 6f 77 20 3d 20 73 66 } //1 ololow = sf
		$a_01_6 = {53 75 62 20 6a 6f 70 28 75 75 75 20 41 73 20 53 74 72 69 6e 67 2c 20 61 61 61 61 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub jop(uuu As String, aaaa As String)
		$a_01_7 = {43 61 6c 6c 20 72 6e 65 65 28 75 75 75 2c 20 61 61 61 61 29 } //1 Call rnee(uuu, aaaa)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}