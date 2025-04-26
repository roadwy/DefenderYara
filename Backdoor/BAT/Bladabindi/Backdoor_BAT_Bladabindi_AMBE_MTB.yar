
rule Backdoor_BAT_Bladabindi_AMBE_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 09 11 08 5d 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Backdoor_BAT_Bladabindi_AMBE_MTB_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 16 11 04 16 1e 28 ?? 00 00 0a 00 07 11 04 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 13 06 02 28 ?? 00 00 0a 13 07 28 ?? 00 00 0a 11 06 11 07 16 11 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 0a de 11 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}