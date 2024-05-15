
rule Trojan_BAT_AgentTesla_MBZH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d d4 07 11 90 01 01 07 8e 69 6a 5d d4 91 08 11 90 01 01 69 6f 90 01 03 0a 61 07 11 90 01 01 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}