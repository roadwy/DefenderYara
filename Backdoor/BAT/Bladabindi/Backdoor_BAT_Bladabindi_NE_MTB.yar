
rule Backdoor_BAT_Bladabindi_NE_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 02 11 06 91 06 61 11 04 08 91 61 b4 9c 08 03 90 01 05 17 da fe 01 13 08 11 08 2c 04 16 0c 2b 05 00 08 17 d6 0c 00 11 06 17 d6 13 06 11 06 11 07 13 09 11 09 31 c5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}