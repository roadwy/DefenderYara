
rule Trojan_BAT_AgentTesla_RDBJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 11 0a 91 11 0e 61 07 11 0f 91 59 13 10 } //00 00 
	condition:
		any of ($a_*)
 
}