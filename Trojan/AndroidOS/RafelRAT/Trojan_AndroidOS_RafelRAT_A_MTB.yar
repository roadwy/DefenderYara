
rule Trojan_AndroidOS_RafelRAT_A_MTB{
	meta:
		description = "Trojan:AndroidOS/RafelRAT.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {35 23 1e 00 46 04 01 03 6e 10 fc bb 04 00 0a 05 38 05 0d 00 6e 10 04 bc 04 00 0c 05 6e 20 25 94 56 00 6e 10 f3 bb 04 00 28 04 6e 10 f3 bb 04 00 d8 03 03 01 28 e6 } //1
		$a_01_1 = {56 69 63 74 69 6d 20 43 6f 6e 6e 65 63 74 65 64 20 3a 20 49 44 } //1 Victim Connected : ID
		$a_01_2 = {52 61 66 65 6c 2d 52 61 74 2d } //1 Rafel-Rat-
		$a_01_3 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 69 70 74 65 64 } //1 Your files have been encripted
		$a_01_4 = {72 65 68 62 65 72 5f 6f 6b 75 } //1 rehber_oku
		$a_01_5 = {73 77 61 67 6b 61 72 6e 61 6c 6f 76 65 73 68 61 6e 64 65 65 72 63 65 6c } //1 swagkarnaloveshandeercel
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}