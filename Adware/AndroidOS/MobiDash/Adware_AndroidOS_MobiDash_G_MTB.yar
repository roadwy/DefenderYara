
rule Adware_AndroidOS_MobiDash_G_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {38 03 57 00 22 01 0e 08 1a 04 90 01 01 4b 70 30 90 01 02 71 04 12 14 6e 20 90 01 02 41 00 0c 04 12 35 90 00 } //1
		$a_03_1 = {22 01 89 08 70 10 90 01 02 01 00 6e 10 90 01 02 01 00 0c 00 54 21 54 1b 6e 20 90 01 02 01 00 90 00 } //1
		$a_03_2 = {0a 00 38 00 08 00 54 a0 53 1b 6e 10 90 01 02 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}