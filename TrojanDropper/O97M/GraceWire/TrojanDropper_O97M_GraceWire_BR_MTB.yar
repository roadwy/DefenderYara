
rule TrojanDropper_O97M_GraceWire_BR_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {45 6e 64 20 49 66 [0-15] 73 4f 66 62 6c 20 3d 20 22 22 22 22 20 2b 20 73 4f 66 62 6c } //1
		$a_03_1 = {76 61 72 52 65 73 31 20 3d 20 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 22 43 41 4c 4c 28 22 20 2b 20 73 4f 66 62 6c 20 26 20 22 22 22 2c 22 22 22 20 2b 20 22 [0-09] 22 22 2c 22 22 4a 22 22 29 22 29 } //1
		$a_03_2 = {2e 54 65 78 74 42 6f 78 33 2e 54 61 67 29 [0-18] 73 65 6e 64 69 6e 67 73 20 3d 20 73 65 6e 64 69 6e 67 73 20 2b 20 31 [0-15] 45 6e 64 20 49 66 } //1
		$a_03_3 = {44 69 6d 20 73 4f 66 62 6c 20 41 73 20 53 74 72 69 6e 67 [0-08] 6f 66 62 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}