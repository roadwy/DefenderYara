
rule Trojan_BAT_AgentTesla_PTGN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {7b e7 00 00 04 6f 39 01 00 0a 28 90 01 01 01 00 0a 7e e5 00 00 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}