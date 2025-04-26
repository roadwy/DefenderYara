
rule TrojanDropper_AndroidOS_Hqwar_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Hqwar.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 21 2f 00 14 04 3b a7 00 00 b0 47 48 04 03 01 d9 08 07 1f dc 09 01 02 48 09 06 09 da 0a 08 4e 91 0a 07 0a b1 87 b0 a7 da 07 07 00 b0 47 93 04 0a 0a db 04 04 01 df 04 04 01 b0 47 94 04 0a 0a b0 47 97 04 07 09 8d 44 4f 04 05 01 14 04 59 8a 7b 00 93 04 0a 04 d8 01 01 01 01 a7 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}