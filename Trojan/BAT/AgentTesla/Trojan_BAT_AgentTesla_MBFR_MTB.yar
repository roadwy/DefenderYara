
rule Trojan_BAT_AgentTesla_MBFR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 1d 06 07 18 6f 90 01 01 00 00 0a 13 05 08 07 18 5b 11 05 1f 10 28 90 01 01 00 00 0a d2 9c 07 18 58 0b 07 06 6f 90 01 01 00 00 0a fe 04 13 06 11 06 2d d4 90 00 } //01 00 
		$a_01_1 = {63 64 39 64 34 39 34 32 31 62 64 66 } //00 00  cd9d49421bdf
	condition:
		any of ($a_*)
 
}