
rule Trojan_AndroidOS_Cerberus_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Cerberus.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 0b 00 35 61 09 00 14 06 de ab 01 00 b3 46 d8 01 01 01 90 01 02 12 01 35 01 2e 00 14 06 3b a7 00 00 b0 64 48 06 02 01 d9 08 04 1f dc 09 01 01 48 09 07 09 da 0a 08 4e 91 0a 04 0a b1 84 b0 a4 da 04 04 00 b0 64 93 06 0a 0a db 06 06 01 df 06 06 01 b0 64 94 06 0a 0a b0 64 b7 94 8d 44 4f 04 05 01 14 04 59 8a 7b 00 93 04 0a 04 d8 01 01 01 01 a4 90 01 02 13 00 13 00 13 01 2f 00 35 10 05 00 d8 00 00 01 90 01 02 22 00 90 01 02 70 20 90 01 02 50 00 11 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}