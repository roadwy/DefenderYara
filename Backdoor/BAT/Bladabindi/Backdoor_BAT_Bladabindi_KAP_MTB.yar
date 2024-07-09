
rule Backdoor_BAT_Bladabindi_KAP_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {10 01 03 28 ?? 00 00 0a 18 5b 17 da 17 d6 8d ?? 00 00 01 0c 07 16 8c ?? 00 00 01 08 17 28 ?? 00 00 0a 18 da } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}