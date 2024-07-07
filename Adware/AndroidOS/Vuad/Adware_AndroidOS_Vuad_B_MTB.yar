
rule Adware_AndroidOS_Vuad_B_MTB{
	meta:
		description = "Adware:AndroidOS/Vuad.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {35 02 16 00 48 03 06 02 62 04 9e 26 94 05 02 01 48 04 04 05 b7 43 da 04 02 1f d4 44 fb 00 b7 43 8d 33 4f 03 06 02 d8 02 02 01 28 eb } //1
		$a_01_1 = {62 00 00 00 14 00 10 00 00 00 14 01 0f 00 00 00 90 00 00 01 94 00 00 01 3c 00 05 00 2a 00 53 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}