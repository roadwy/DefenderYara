
rule TrojanDropper_AndroidOS_SAgnt_E_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {21 13 35 32 0b 00 48 03 01 02 b7 03 8d 33 4f 03 01 02 d8 02 02 01 28 f5 22 00 ?? ?? 62 02 ?? ?? 70 30 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}