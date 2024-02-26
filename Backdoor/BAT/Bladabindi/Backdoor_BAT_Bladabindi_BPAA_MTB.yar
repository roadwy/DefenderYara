
rule Backdoor_BAT_Bladabindi_BPAA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.BPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {72 1f 00 00 70 80 90 01 01 00 00 04 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 80 90 01 01 00 00 04 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}