
rule TrojanDropper_O97M_GraceWire_DC_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 52 50 20 3d 20 22 25 22 20 26 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 PRP = "%" & Dialog4.TextBox1.Tag
		$a_01_1 = {53 65 74 20 63 61 72 20 3d 20 4e 65 77 20 52 65 70 6f 73 69 74 6f 72 } //1 Set car = New Repositor
		$a_03_2 = {44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 90 02 08 2c 20 22 45 78 70 22 20 2b 20 22 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 50 52 50 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 25 22 29 90 00 } //1
		$a_01_3 = {43 68 44 69 72 20 28 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 22 29 } //1 ChDir (Dialog4.TextBox1.Tag + "")
		$a_01_4 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 57 75 7a 7a 79 42 75 64 } //1 Public Function WuzzyBud
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}