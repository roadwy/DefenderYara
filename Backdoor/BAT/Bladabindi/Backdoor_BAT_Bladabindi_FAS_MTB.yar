
rule Backdoor_BAT_Bladabindi_FAS_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.FAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 07 06 91 61 b4 9c 06 03 6f ?? 00 00 0a 17 da 33 04 16 0a 2b 04 06 17 d6 0a 11 05 17 d6 13 05 11 05 11 06 31 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}