
rule Trojan_BAT_AgentTesla_PQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {1f 5d 1f 2d 28 90 01 04 16 9a 1c d0 90 01 09 1f 0f 20 90 01 0e 14 14 14 6f 90 01 04 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}