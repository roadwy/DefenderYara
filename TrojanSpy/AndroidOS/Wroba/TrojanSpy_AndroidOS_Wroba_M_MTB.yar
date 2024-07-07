
rule TrojanSpy_AndroidOS_Wroba_M_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 00 04 23 44 30 00 90 01 06 0a 05 12 f6 90 01 04 70 40 90 01 01 00 98 42 0e 00 12 06 35 56 0b 00 48 07 04 06 b7 17 8d 77 4f 07 04 06 d8 06 06 01 28 f6 90 01 06 28 e6 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}