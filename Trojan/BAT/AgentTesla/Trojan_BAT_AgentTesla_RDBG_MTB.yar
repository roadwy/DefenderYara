
rule Trojan_BAT_AgentTesla_RDBG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 17 58 11 90 01 01 5d 13 90 01 01 07 06 91 11 90 01 01 61 07 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}