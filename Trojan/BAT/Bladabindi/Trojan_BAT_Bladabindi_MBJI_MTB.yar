
rule Trojan_BAT_Bladabindi_MBJI_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e 69 03 8e 69 da 04 8e 69 d6 17 da 17 d6 8d 90 01 01 00 00 01 0b 02 16 07 16 08 28 90 01 01 00 00 0a 00 04 16 07 08 04 8e 69 90 00 } //1
		$a_01_1 = {34 37 31 62 2d 39 36 66 38 2d 61 61 34 62 61 38 61 66 39 65 66 62 } //1 471b-96f8-aa4ba8af9efb
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}