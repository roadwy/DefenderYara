
rule Trojan_BAT_AgentTesla_PTGT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 01 00 00 0a dc 07 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 28 90 01 01 01 00 0a 6f 1e 01 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}