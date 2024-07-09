
rule Backdoor_BAT_Bladabindi_SL_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 18 9a 1f 10 7e 9b 02 00 04 28 ?? ?? ?? 06 86 6f ?? ?? ?? 0a 11 18 17 d6 13 18 11 18 11 17 3e da ff ff ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}