
rule TrojanDropper_O97M_GraceWire_DE_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {64 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 45 78 63 65 6c 43 2c 20 22 45 78 65 63 75 22 20 2b 20 22 74 65 45 22 20 2b 20 22 78 63 65 6c 34 4d 61 63 72 6f 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 43 41 4c 22 20 2b 20 22 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 [0-10] 22 22 2c 22 22 4a 22 22 29 22 29 } //1
		$a_01_1 = {50 72 69 76 61 74 65 20 53 75 62 20 54 65 78 74 42 6f 78 33 5f 43 68 61 6e 67 65 28 29 } //1 Private Sub TextBox3_Change()
		$a_01_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 56 6f 6f 6f 6f 6f 68 65 61 64 28 29 } //1 Public Function Vooooohead()
		$a_01_3 = {44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 Dialog4.TextBox1.Tag
		$a_03_4 = {50 75 62 6c 69 63 20 53 75 62 20 56 69 73 74 61 51 28 57 68 65 72 65 54 6f 47 6f 29 [0-08] 44 6f 45 76 65 6e 74 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}