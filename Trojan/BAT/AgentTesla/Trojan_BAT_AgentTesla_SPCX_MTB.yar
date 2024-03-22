
rule Trojan_BAT_AgentTesla_SPCX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {5d d4 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 11 05 17 6a 58 13 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}