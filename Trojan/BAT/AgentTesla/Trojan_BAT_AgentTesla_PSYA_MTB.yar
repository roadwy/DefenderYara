
rule Trojan_BAT_AgentTesla_PSYA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 28 07 00 00 0a 6f 08 00 00 0a 6f 09 00 00 0a 28 0a 00 00 0a 26 00 2b e7 } //00 00 
	condition:
		any of ($a_*)
 
}