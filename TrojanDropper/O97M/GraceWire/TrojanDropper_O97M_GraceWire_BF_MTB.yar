
rule TrojanDropper_O97M_GraceWire_BF_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6f 66 62 6c 20 3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c [0-10] 2e 64 6c 6c 22 } //1
		$a_03_1 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 2c 20 22 5c [0-10] 2e 78 6c 73 } //1
		$a_03_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-10] 2c 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65 29 2c 20 22 22 29 } //1
		$a_03_3 = {3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 [0-08] 44 69 6d 20 6f 66 62 6c 20 41 73 20 53 74 72 69 6e 67 } //1
		$a_03_4 = {44 6f 45 76 65 6e 74 73 [0-15] 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 2e 43 6f 70 79 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}