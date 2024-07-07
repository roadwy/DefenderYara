
rule TrojanDropper_O97M_Hancitor_JAH_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 74 69 63 2e 64 6c 6c } //1 Static.dll
		$a_01_1 = {53 75 62 20 63 68 65 63 6b 74 68 65 28 73 66 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub checkthe(sf As String)
		$a_01_2 = {44 69 6d 20 70 61 66 68 20 41 73 20 53 74 72 69 6e 67 } //1 Dim pafh As String
		$a_01_3 = {70 61 66 68 20 3d 20 69 65 70 } //1 pafh = iep
		$a_01_4 = {44 69 6d 20 6f 61 73 73 20 41 73 20 53 74 72 69 6e 67 } //1 Dim oass As String
		$a_01_5 = {6f 61 73 73 20 3d 20 22 6d 22 20 26 20 22 70 22 } //1 oass = "m" & "p"
		$a_01_6 = {44 69 6d 20 6f 6c 6f 6c 6f 77 20 41 73 20 53 74 72 69 6e 67 } //1 Dim ololow As String
		$a_01_7 = {6f 6c 6f 6c 6f 77 20 3d 20 73 66 } //1 ololow = sf
		$a_01_8 = {53 75 62 20 6a 6f 70 28 75 75 75 20 41 73 20 53 74 72 69 6e 67 2c 20 61 61 61 61 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub jop(uuu As String, aaaa As String)
		$a_01_9 = {43 61 6c 6c 20 6e 6d 28 6f 6c 6f 6c 6f 77 29 } //1 Call nm(ololow)
		$a_01_10 = {43 61 6c 6c 20 72 6e 65 65 28 75 75 75 2c 20 61 61 61 61 29 } //1 Call rnee(uuu, aaaa)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}