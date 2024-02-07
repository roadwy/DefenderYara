
rule Trojan_BAT_AgentTesla_MBDL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 00 32 00 58 00 5a 00 5a 00 5a 00 58 00 49 00 49 00 69 00 69 00 69 00 69 00 4f 00 4f 00 4f 00 6f 00 69 00 69 00 69 00 69 00 4f 00 30 00 30 00 } //00 00  22XZZZXIIiiiiOOOoiiiiO00
	condition:
		any of ($a_*)
 
}