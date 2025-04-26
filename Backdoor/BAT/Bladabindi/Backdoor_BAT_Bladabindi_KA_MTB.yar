
rule Backdoor_BAT_Bladabindi_KA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0e 91 61 b4 9c 11 0e 03 6f ?? 00 00 0a 17 da 33 05 16 13 0e 2b 06 11 0e 17 d6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}