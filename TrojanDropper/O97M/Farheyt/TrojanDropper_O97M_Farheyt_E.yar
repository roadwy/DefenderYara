
rule TrojanDropper_O97M_Farheyt_E{
	meta:
		description = "TrojanDropper:O97M/Farheyt.E,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 31 32 29 20 3d 20 90 10 03 00 [0-05] 28 30 29 20 3d 20 90 10 03 00 [0-05] 28 31 29 20 3d 20 90 10 03 00 [0-05] 28 32 29 20 3d 20 90 10 03 00 [0-05] 28 33 29 20 3d 20 90 10 03 00 [0-05] 28 34 29 20 3d 20 [0-10] 41 73 20 4f 62 6a 65 63 74 [0-10] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 1d 10 00 28 90 1d 10 00 2c 20 90 1d 10 00 29 29 [0-10] 2e 52 75 6e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDropper_O97M_Farheyt_E_2{
	meta:
		description = "TrojanDropper:O97M/Farheyt.E,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-08] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 52 54 46 } //1
		$a_00_1 = {20 2b 20 54 45 54 45 } //1  + TETE
		$a_00_2 = {20 2b 20 4a 4e 42 42 48 } //1  + JNBBH
		$a_00_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 6f } //1 = CreateObject("Wo
		$a_00_4 = {2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 .Application")
		$a_02_5 = {45 6e 76 69 72 6f 6e 24 28 [0-0a] 29 20 2b } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}