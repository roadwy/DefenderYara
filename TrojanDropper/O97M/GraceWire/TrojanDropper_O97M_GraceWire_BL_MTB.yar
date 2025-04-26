
rule TrojanDropper_O97M_GraceWire_BL_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6f 66 62 6c 20 3d 20 [0-10] 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c [0-10] 2e 64 6c 6c } //1
		$a_03_1 = {63 74 61 63 6b 50 75 70 20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-08] 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 2c 20 22 5c [0-10] 2e 78 6c 73 } //1
		$a_03_2 = {63 74 61 63 6b 50 6f 70 20 3d 20 64 65 72 73 68 6c 65 70 20 2b 20 [0-08] 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}