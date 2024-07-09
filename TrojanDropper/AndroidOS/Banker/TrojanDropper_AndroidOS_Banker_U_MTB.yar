
rule TrojanDropper_AndroidOS_Banker_U_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {35 04 0f 00 48 05 01 04 dc 06 04 01 48 06 03 06 b7 65 8d 55 4f 05 02 04 d8 04 04 01 28 f2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}