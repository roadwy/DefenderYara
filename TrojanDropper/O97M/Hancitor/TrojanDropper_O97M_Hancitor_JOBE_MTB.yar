
rule TrojanDropper_O97M_Hancitor_JOBE_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOBE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 68 66 64 77 65 73 64 66 28 29 } //1 Sub hfdwesdf()
		$a_01_1 = {43 61 6c 6c 20 6d 6d 28 22 70 3a 22 20 26 20 22 2f 2f 22 29 } //1 Call mm("p:" & "//")
		$a_01_2 = {43 61 6c 6c 20 78 63 76 73 64 66 73 } //1 Call xcvsdfs
		$a_01_3 = {49 66 20 44 69 72 28 75 75 20 26 20 22 5c 6d 6f 65 22 20 26 20 22 78 78 22 20 26 20 70 6c 66 20 26 20 22 62 22 20 26 20 22 69 22 20 26 20 22 6e 22 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(uu & "\moe" & "xx" & plf & "b" & "i" & "n", vbDirectory) = "" Then
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}