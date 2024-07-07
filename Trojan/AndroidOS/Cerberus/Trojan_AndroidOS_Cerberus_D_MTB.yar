
rule Trojan_AndroidOS_Cerberus_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Cerberus.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 08 35 28 90 01 02 d8 01 01 b2 48 04 03 08 14 05 ed 97 05 00 b0 15 dc 09 08 01 48 09 07 09 db 0a 01 3d b0 5a da 0b 0a 00 b3 5b b0 0b b0 4b 93 04 01 01 d8 04 04 ff b0 4b b4 11 b0 1b 97 01 0b 09 8d 11 4f 01 06 08 14 01 f3 9a 0e 00 14 04 fa 48 0b 00 92 09 05 0a b1 19 b0 94 d8 08 08 01 01 a1 28 d1 13 00 0e 00 13 02 33 00 35 20 0b 00 93 02 04 05 91 02 01 02 d8 05 02 3b d8 00 00 01 28 f4 22 00 90 01 02 70 20 90 01 02 60 00 11 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}