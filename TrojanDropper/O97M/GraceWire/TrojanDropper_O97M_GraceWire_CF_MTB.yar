
rule TrojanDropper_O97M_GraceWire_CF_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {63 74 61 63 6b 50 75 70 20 3d 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c 90 02 08 22 90 00 } //1
		$a_03_1 = {63 74 61 63 6b 50 75 70 20 3d 20 63 74 61 63 6b 50 75 70 20 2b 20 22 90 02 08 2e 78 6c 73 78 22 90 00 } //1
		$a_01_2 = {63 74 61 63 6b 50 6f 70 20 3d 20 64 65 72 73 68 6c 65 70 20 26 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65 } //1 ctackPop = dershlep & Dialog4.TextBox3.Value
		$a_01_3 = {6f 66 62 6c 20 3d 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 } //1 ofbl = Dialog4.TextBox3.Tag
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}