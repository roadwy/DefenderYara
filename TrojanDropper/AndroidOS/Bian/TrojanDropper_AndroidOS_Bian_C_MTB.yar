
rule TrojanDropper_AndroidOS_Bian_C_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Bian.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {12 01 35 21 2c 00 14 06 3b a7 00 00 b0 64 48 06 03 01 d9 09 04 1f dc 0a 01 02 48 0a 08 0a da 0b 09 4e 91 0b 04 0b da 04 04 00 b3 94 b0 04 b0 64 93 06 0b 0b d8 06 06 ff b0 64 94 06 0b 0b b0 64 b7 a4 8d 44 4f 04 07 01 14 04 59 8a 7b 00 93 04 0b 04 d8 01 01 01 01 b4 28 d5 13 00 2f 00 35 05 05 00 d8 05 05 01 28 fa 22 00 90 01 02 70 20 90 01 02 70 00 11 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}