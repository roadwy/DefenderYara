
rule TrojanDropper_O97M_GraceWire_DT_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {44 6f 45 76 65 6e 74 73 90 0c 02 00 45 78 43 68 61 6e 67 65 4d 6f 6e 65 79 90 0c 02 00 44 6f 45 76 65 6e 74 73 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //1
		$a_03_1 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 31 39 39 39 39 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //1
		$a_01_2 = {43 68 65 63 6b 43 61 72 20 3d 20 63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 26 20 44 72 69 76 65 29 } //1 CheckCar = car.SpecialFolders("" & Drive)
		$a_01_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 45 78 43 68 61 6e 67 65 4d 6f 6e 65 79 28 29 } //1 Public Function ExChangeMoney()
		$a_01_4 = {64 65 72 73 68 6c 65 70 20 3d 20 22 22 20 26 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 dershlep = "" & Form0.TextBox1.Tag
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDropper_O97M_GraceWire_DT_MTB_2{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {44 6f 45 76 65 6e 74 73 90 0c 02 00 45 78 43 68 61 6e 67 65 4d 6f 6e 65 79 90 0c 02 00 44 6f 45 76 65 6e 74 73 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //1
		$a_03_1 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 31 39 39 39 39 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //1
		$a_01_2 = {43 68 65 63 6b 43 61 72 20 3d 20 63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 26 20 44 72 69 76 65 29 } //1 CheckCar = car.SpecialFolders("" & Drive)
		$a_01_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 45 78 43 68 61 6e 67 65 4d 6f 6e 65 79 28 29 } //1 Public Function ExChangeMoney()
		$a_01_4 = {64 65 72 73 68 6c 65 70 20 3d 20 22 22 20 2b 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 dershlep = "" + Form0.TextBox1.Tag
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}