
rule Trojan_BAT_AgentTesla_RA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d 03 26 2b 03 0a 2b 00 06 90 01 01 2d 49 26 06 17 58 90 01 01 2d 49 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}