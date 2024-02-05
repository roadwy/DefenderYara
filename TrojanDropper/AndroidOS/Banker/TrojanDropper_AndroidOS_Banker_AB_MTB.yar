
rule TrojanDropper_AndroidOS_Banker_AB_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_00_0 = {35 05 1b 00 92 06 04 07 48 08 01 05 b0 64 b0 74 dc 07 05 02 48 07 03 07 d0 69 16 14 d0 99 2c f8 b0 49 b7 87 8d 77 4f 07 02 05 b0 96 b1 46 d8 05 05 01 01 97 28 e6 } //05 00 
		$a_00_1 = {35 15 1d 00 b0 a9 48 0b 02 05 90 0c 09 0a dc 0d 05 02 48 0d 07 0d b0 c9 d2 aa 35 1b b0 a9 97 0a 0b 0d 8d aa 4f 0a 03 05 14 0a 53 c9 03 00 b1 9a b0 ca d8 05 05 01 01 c9 28 e4 } //00 00 
	condition:
		any of ($a_*)
 
}