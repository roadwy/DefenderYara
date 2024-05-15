
rule Trojan_BAT_AgentTesla_RDAY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 11 01 28 01 00 00 2b 28 02 00 00 2b 16 11 01 8e 69 } //00 00 
	condition:
		any of ($a_*)
 
}