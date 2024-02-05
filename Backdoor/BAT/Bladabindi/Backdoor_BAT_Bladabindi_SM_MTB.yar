
rule Backdoor_BAT_Bladabindi_SM_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 1f 1a 0b 1f 4e 0c 28 90 01 0e 6f 90 01 04 0d 09 72 90 01 09 13 04 73 90 01 04 13 05 11 04 17 8d 90 01 04 25 16 11 05 6f 90 01 04 a2 28 90 01 04 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}