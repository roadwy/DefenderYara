
rule Backdoor_BAT_Bladabindi_SV_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 08 09 1e d8 1e 6f 26 00 00 0a 18 28 27 00 00 0a 9c 09 17 d6 0d 09 11 04 13 05 11 05 31 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}