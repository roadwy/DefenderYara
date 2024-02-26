
rule Trojan_BAT_AgentTesla_PTCG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 19 00 00 0a 0b 28 90 01 01 00 00 0a 16 9a 6f 1b 00 00 0a 0c 07 28 90 01 01 00 00 0a 0d 09 12 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}