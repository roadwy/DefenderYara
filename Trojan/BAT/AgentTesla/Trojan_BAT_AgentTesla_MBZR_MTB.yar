
rule Trojan_BAT_AgentTesla_MBZR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 91 08 11 90 01 01 1f 90 01 01 5d 6f 90 01 03 0a 61 13 90 01 01 11 90 01 01 11 90 01 01 59 20 00 01 00 00 58 20 00 01 00 00 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}