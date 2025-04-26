
rule Backdoor_BAT_Bladabindi_AAWQ_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AAWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 13 05 09 13 06 11 05 11 06 30 37 02 11 04 28 ?? 00 00 0a 03 11 04 03 6f ?? 00 00 0a 5d 07 d6 28 ?? 00 00 0a da 13 07 06 11 07 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 11 04 17 d6 13 04 2b bc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}