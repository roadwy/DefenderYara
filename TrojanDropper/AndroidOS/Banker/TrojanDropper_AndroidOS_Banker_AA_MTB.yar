
rule TrojanDropper_AndroidOS_Banker_AA_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 12 31 00 d8 08 08 52 14 07 50 2e 97 00 91 04 07 04 da 07 08 50 91 07 04 07 da 08 08 00 b3 78 b0 08 48 09 03 02 b0 98 93 09 04 04 d8 09 09 ff b0 98 94 09 04 04 b0 98 dc 09 02 03 48 09 06 09 b7 98 8d 88 4f 08 05 02 13 08 24 00 b3 78 b0 48 d8 08 08 a8 d8 02 02 01 01 8a 01 48 01 74 01 a7 28 d0 } //5
	condition:
		((#a_00_0  & 1)*5) >=5
 
}