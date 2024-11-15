
rule Backdoor_BAT_Bladabindi_SQ_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 02 11 05 91 06 61 09 08 91 61 b4 9c 08 03 6f 37 00 00 0a 17 da fe 01 13 07 11 07 2c 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}