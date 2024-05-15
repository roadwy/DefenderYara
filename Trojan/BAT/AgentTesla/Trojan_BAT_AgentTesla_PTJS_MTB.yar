
rule Trojan_BAT_AgentTesla_PTJS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 2d 00 00 0a 07 28 2e 00 00 0a 6f 2f 00 00 0a 28 21 00 00 06 28 03 00 00 2b 7e 1e 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}