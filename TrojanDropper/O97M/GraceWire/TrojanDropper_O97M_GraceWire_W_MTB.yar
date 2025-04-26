
rule TrojanDropper_O97M_GraceWire_W_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.W!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {26 20 22 2e 64 [0-06] 6c [0-09] 6c 22 } //1
		$a_01_1 = {43 61 6c 6c 20 6c 57 2e 72 69 74 65 28 6f 75 74 66 70 2c } //1 Call lW.rite(outfp,
		$a_01_2 = {6f 75 74 70 75 74 2e 72 61 77 22 } //1 output.raw"
		$a_03_3 = {3d 20 54 65 78 74 42 6f 78 31 54 61 67 20 2b [0-14] 7a [0-06] 69 [0-06] 70 [0-06] 22 } //1
		$a_03_4 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}