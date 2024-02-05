
rule Backdoor_BAT_Bladabindi_MOB_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {07 0c 06 72 90 01 09 0d 09 72 90 01 09 13 04 11 04 14 72 90 01 04 18 8d 90 01 04 25 17 17 8d 90 01 04 25 16 08 6f 90 01 04 a2 a2 14 14 28 90 01 05 1f 49 13 05 2b 00 11 05 2a 90 09 1e 00 28 90 01 0e 0a 1b 73 90 01 04 0b 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}