
rule Trojan_BAT_AgentTesla_PTKE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 11 00 00 0a 02 7b 20 00 00 04 6f 12 00 00 0a 02 02 fe 06 4e 00 00 06 73 24 00 00 0a 28 90 01 01 00 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}