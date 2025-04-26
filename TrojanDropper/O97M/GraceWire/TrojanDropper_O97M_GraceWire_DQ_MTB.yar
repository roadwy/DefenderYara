
rule TrojanDropper_O97M_GraceWire_DQ_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 52 65 64 42 75 74 74 6f 6e 28 64 49 6d 6d 65 72 20 41 73 20 44 6f 75 62 6c 65 29 } //1 Public Function RedButton(dImmer As Double)
		$a_01_1 = {73 20 3d 20 22 4e 20 68 65 61 6c 74 68 20 70 72 6f 62 6c 65 6d 73 } //1 s = "N health problems
		$a_01_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 56 6f 6f 6f 6f 6f 68 65 61 64 28 29 } //1 Public Function Vooooohead()
		$a_01_3 = {52 61 6e 67 65 28 22 4c 32 22 29 2e 46 6f 72 6d 75 6c 61 20 3d 20 22 24 30 22 } //1 Range("L2").Formula = "$0"
		$a_03_4 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 31 39 39 39 39 90 0c 02 00 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}