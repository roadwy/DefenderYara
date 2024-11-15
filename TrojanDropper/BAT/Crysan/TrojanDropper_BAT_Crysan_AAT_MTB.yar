
rule TrojanDropper_BAT_Crysan_AAT_MTB{
	meta:
		description = "TrojanDropper:BAT/Crysan.AAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 15 28 ?? ?? ?? 06 26 11 06 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 61 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}