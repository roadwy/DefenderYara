
rule TrojanDropper_AndroidOS_Banker_I_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {12 02 35 12 30 00 d8 08 08 5d 48 05 03 02 14 09 40 be 00 00 91 04 09 04 dc 09 02 02 48 09 07 09 14 0a 6e 83 03 00 b3 8a b0 4a b3 88 d8 08 08 ff b0 58 91 05 0a 04 da 05 05 00 b0 58 93 05 04 04 dc 05 05 01 b0 58 97 05 08 09 8d 55 4f 05 06 02 14 05 4c 4d 93 00 b3 45 d8 02 02 01 01 48 01 a4 28 d1 13 01 22 00 35 10 05 00 d8 00 00 01 28 fa 22 00 90 01 02 70 20 90 01 02 60 00 11 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}