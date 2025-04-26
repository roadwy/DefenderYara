
rule Trojan_AndroidOS_Cerberus_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Cerberus.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 04 35 24 2d 00 14 08 6d 42 06 00 b1 81 48 08 03 04 14 09 87 6a 0d 00 b0 97 dc 09 04 01 48 09 06 09 14 0a b1 65 0c 00 93 0b 01 07 b0 ba da 0b 07 00 b3 1b b0 0b b0 8b 93 01 0a 0a d8 01 01 ff b0 1b 94 01 0a 0a b0 1b 97 01 0b 09 8d 11 4f 01 05 04 d8 04 04 01 01 71 01 a7 28 d4 12 70 13 01 0e 00 35 10 07 00 d3 71 83 13 d8 00 00 01 28 f8 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}