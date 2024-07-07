
rule TrojanDropper_AndroidOS_SAgnt_N_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 00 0b 01 13 08 10 00 a5 08 01 08 17 0a 00 00 ff ff c0 a8 a5 0a 10 03 c2 4a c2 8a 2a 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}