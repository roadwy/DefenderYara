
rule TrojanDropper_O97M_Nemucod_A{
	meta:
		description = "TrojanDropper:O97M/Nemucod.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 22 65 73 6a 2e 22 29 29 0d 0a 76 62 5f } //1
		$a_03_1 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 76 62 5f [0-10] 28 22 6c 6c 65 68 53 2e 74 70 69 72 63 53 57 22 29 29 } //1
		$a_01_2 = {28 22 6e 75 52 22 29 } //1 ("nuR")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}