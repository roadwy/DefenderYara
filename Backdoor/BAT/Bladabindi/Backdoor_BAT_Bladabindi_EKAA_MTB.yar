
rule Backdoor_BAT_Bladabindi_EKAA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.EKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e b7 1f 11 da 17 d6 8d 90 01 01 00 00 01 13 04 06 1f 10 11 04 16 06 8e b7 1f 10 da 28 90 01 01 00 00 0a 00 11 04 0c 2b 00 08 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}