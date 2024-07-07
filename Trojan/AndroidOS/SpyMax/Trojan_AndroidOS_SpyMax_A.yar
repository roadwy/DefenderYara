
rule Trojan_AndroidOS_SpyMax_A{
	meta:
		description = "Trojan:AndroidOS/SpyMax.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 74 74 72 71 65 66 76 71 72 65 76 61 67 79 71 7a 74 77 77 7a 79 71 34 31 35 39 } //1 tttrqefvqrevagyqztwwzyq4159
		$a_01_1 = {78 77 6d 67 63 65 6a 34 31 36 31 } //1 xwmgcej4161
		$a_01_2 = {51 64 54 52 49 57 55 78 34 31 35 37 } //1 QdTRIWUx4157
		$a_01_3 = {61 68 62 7a 76 71 62 66 75 34 31 35 38 } //1 ahbzvqbfu4158
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}