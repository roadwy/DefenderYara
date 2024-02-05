
rule Trojan_BAT_AgentTesla_MBFN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 1c 06 07 18 6f 90 01 01 00 00 0a 13 05 08 07 18 5b 11 05 1f 10 28 90 01 01 00 00 0a 9c 07 18 58 0b 07 06 6f 90 01 01 00 00 0a fe 04 13 06 11 06 2d d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}