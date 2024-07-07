
rule Trojan_AndroidOS_Cerberus_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Cerberus.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 01 35 21 2f 00 14 05 3b a7 00 00 b0 56 48 05 04 01 d9 09 06 1f dc 0a 01 03 48 0a 08 0a da 0b 09 4e 91 0b 06 0b b1 96 b0 b6 da 06 06 00 b0 56 93 05 0b 0b db 05 05 01 df 05 05 01 b0 56 94 05 0b 0b b0 56 97 05 06 0a 8d 55 4f 05 07 01 14 05 59 8a 7b 00 93 05 0b 05 d8 01 01 01 01 b6 90 01 02 13 00 2f 00 35 03 05 00 d8 03 03 01 90 01 02 22 00 90 01 02 70 20 90 01 02 70 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}