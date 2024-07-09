
rule TrojanDropper_O97M_GraceWire_O_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.O!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 41 72 72 61 79 } //1 KillArray
		$a_01_1 = {43 61 6c 6c 20 6c 57 2e 72 69 74 65 28 6f 75 74 66 70 2c } //1 Call lW.rite(outfp,
		$a_01_2 = {6f 75 74 70 75 74 2e 72 61 77 22 } //1 output.raw"
		$a_03_3 = {50 75 62 6c 69 63 20 53 75 62 20 4b 69 6c 6c 41 72 72 61 79 28 [0-25] 28 29 20 41 73 20 56 61 72 69 61 6e 74 29 [0-10] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 } //1
		$a_03_4 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}