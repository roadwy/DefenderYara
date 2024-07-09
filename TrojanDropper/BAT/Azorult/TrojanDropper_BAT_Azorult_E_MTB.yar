
rule TrojanDropper_BAT_Azorult_E_MTB{
	meta:
		description = "TrojanDropper:BAT/Azorult.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 03 6f 1f 00 00 0a 7e 07 00 00 04 03 7e 07 00 00 04 6f 1d 00 00 0a 5d 6f 1f 00 00 0a 61 [0-30] 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}