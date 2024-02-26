
rule Trojan_BAT_AgentTesla_PTGP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 4b 00 00 70 6f 05 00 00 06 0c 28 90 01 01 00 00 0a 06 72 7b 00 00 70 28 90 01 01 00 00 0a 6f 04 00 00 06 6f 08 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}