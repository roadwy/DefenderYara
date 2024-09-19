
rule Adware_AndroidOS_Adlo_B_MTB{
	meta:
		description = "Adware:AndroidOS/Adlo.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 03 00 08 48 04 02 08 dd 04 04 1f b7 43 8e 33 50 03 00 08 d8 08 08 01 } //1
		$a_03_1 = {12 40 23 00 ?? 00 12 01 4d 02 00 01 62 02 05 00 12 11 4d 02 00 01 12 02 12 21 4d 02 00 01 12 32 4d 03 00 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}