
rule Trojan_BAT_AgentTesla_GPC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 08 5d 13 90 01 01 07 11 90 01 01 91 11 90 01 01 09 1f 90 01 01 5d 91 61 13 90 01 01 07 11 90 01 01 11 90 01 01 07 09 17 58 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}