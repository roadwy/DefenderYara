
rule TrojanDropper_O97M_GraceWire_K_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.K!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {23 49 66 20 56 42 41 37 90 02 20 54 68 65 6e 90 00 } //1
		$a_01_1 = {4b 69 6c 6c 41 72 72 61 79 } //1 KillArray
		$a_01_2 = {6f 75 74 66 70 20 3d 20 6c 4f 2e 70 65 6e 28 22 6f 75 74 70 75 74 2e 72 61 77 22 2c 20 31 29 } //1 outfp = lO.pen("output.raw", 1)
		$a_03_3 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d 90 01 01 2e 54 65 78 74 42 6f 78 90 01 01 2e 54 61 67 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}