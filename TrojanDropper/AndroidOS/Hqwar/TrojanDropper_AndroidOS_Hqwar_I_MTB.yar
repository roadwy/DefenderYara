
rule TrojanDropper_AndroidOS_Hqwar_I_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Hqwar.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {01 25 12 02 35 12 2c 00 14 05 54 03 05 00 90 0a 08 05 13 05 26 00 b3 a5 b0 85 93 09 0a 0a d8 09 09 ff 48 0b 03 02 b0 b9 92 08 08 05 da 08 08 00 b0 89 93 08 05 05 dc 08 08 01 b0 89 dc 08 02 02 48 08 07 08 b7 98 8d 88 4f 08 04 02 da 08 05 35 db 09 0a 44 b1 98 d8 02 02 01 } //00 00 
	condition:
		any of ($a_*)
 
}