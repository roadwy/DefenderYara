
rule Backdoor_BAT_Bladabindi_KAU_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b7 07 11 0b 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 11 0b 18 d6 13 0b 11 0b 11 0a 31 cf 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}