
rule TrojanDropper_AndroidOS_SAgnt_L_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 28 14 00 12 04 21 16 35 64 0d 00 48 06 01 04 48 07 03 08 b7 76 8d 66 4f 06 01 04 d8 04 04 01 28 f3 d8 08 08 01 28 ed } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}