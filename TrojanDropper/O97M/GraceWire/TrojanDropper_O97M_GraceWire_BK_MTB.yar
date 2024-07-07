
rule TrojanDropper_O97M_GraceWire_BK_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 52 50 20 3d 20 22 25 22 20 2b 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 PRP = "%" + UserForm6.TextBox1.Tag
		$a_01_1 = {26 20 55 73 65 72 46 6f 72 6d 36 2e 4c 61 62 65 6c 31 2e 54 61 67 2c 20 6f 66 62 6c 2c } //1 & UserForm6.Label1.Tag, ofbl,
		$a_03_2 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 6f 66 62 6c 20 26 20 22 22 22 2c 22 22 90 02 05 22 22 2c 22 22 4a 22 22 29 22 90 00 } //1
		$a_03_3 = {44 6f 45 76 65 6e 74 73 90 02 15 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 2e 43 6f 70 79 90 00 } //1
		$a_01_4 = {43 68 44 69 72 20 28 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 29 } //1 ChDir (UserForm6.TextBox1.Tag)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}