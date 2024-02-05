
rule Backdoor_BAT_SpyGate_DCC_MTB{
	meta:
		description = "Backdoor:BAT/SpyGate.DCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {1b 11 05 a2 00 11 09 1c 11 08 a2 00 11 09 28 90 01 04 28 90 01 04 28 90 01 04 28 90 01 04 0b 28 90 01 04 07 6f 90 01 04 6f 90 01 04 14 14 6f 90 01 04 74 90 01 04 13 06 00 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}