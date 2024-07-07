
rule TrojanDropper_O97M_GraceWire_CM_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 4f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 73 65 6e 64 69 6e 67 73 43 53 54 52 20 2b 20 22 2e 64 6c 6c 22 } //1 sOfbl = ofbl + sendingsCSTR + ".dll"
		$a_01_1 = {49 66 20 48 69 64 64 65 6e 45 45 34 4d 28 73 4f 66 62 6c 29 20 54 68 65 6e } //1 If HiddenEE4M(sOfbl) Then
		$a_01_2 = {73 4f 66 62 6c 20 26 20 22 22 22 2c 22 22 22 } //1 sOfbl & ""","""
		$a_03_3 = {76 61 72 52 65 73 31 20 3d 20 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 22 43 41 4c 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 90 02 10 22 22 2c 22 22 4a 22 22 29 22 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}