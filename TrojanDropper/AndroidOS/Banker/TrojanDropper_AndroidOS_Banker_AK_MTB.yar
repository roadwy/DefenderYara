
rule TrojanDropper_AndroidOS_Banker_AK_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AK!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 02 2f 00 14 04 3b a7 00 00 b0 47 48 04 03 02 d9 06 07 1f dc 09 02 03 48 09 08 09 da 0a 06 4e 91 0a 07 0a b1 67 b0 a7 da 07 07 00 b0 47 93 04 0a 0a db 04 04 01 df 04 04 01 b0 47 94 04 0a 0a b0 47 97 04 07 09 8d 44 4f 04 05 02 14 04 59 8a 7b 00 93 04 0a 04 d8 02 02 01 01 a7 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}