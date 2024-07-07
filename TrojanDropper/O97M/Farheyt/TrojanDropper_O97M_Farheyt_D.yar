
rule TrojanDropper_O97M_Farheyt_D{
	meta:
		description = "TrojanDropper:O97M/Farheyt.D,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 90 02 02 44 69 6d 20 90 02 10 20 41 73 20 56 61 72 69 61 6e 74 90 02 60 46 6f 72 20 90 02 10 20 3d 20 90 02 02 20 54 6f 20 90 02 40 4c 63 61 73 65 28 22 90 02 08 22 29 20 2b 20 4c 63 61 73 65 28 22 90 02 08 22 29 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}