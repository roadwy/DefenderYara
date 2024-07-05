
rule Trojan_BAT_AgentTesla_RDBH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 90 01 01 07 11 90 01 01 91 11 90 01 01 61 07 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}