
rule Trojan_BAT_AgentTesla_PSYF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 05 00 00 0a 28 01 00 00 2b 6f 07 00 00 0a 0a 06 16 06 6f 08 00 00 0a 6f 09 00 00 0a 0a 06 } //00 00 
	condition:
		any of ($a_*)
 
}