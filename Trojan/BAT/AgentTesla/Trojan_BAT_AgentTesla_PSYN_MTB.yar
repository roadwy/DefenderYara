
rule Trojan_BAT_AgentTesla_PSYN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 11 05 02 6f 11 00 00 0a 00 11 05 6f 12 00 00 0a 00 11 04 16 6a 16 6f 13 00 00 0a 26 07 11 04 7e 17 00 00 0a 6f 15 00 00 0a 00 00 de 0d } //00 00 
	condition:
		any of ($a_*)
 
}