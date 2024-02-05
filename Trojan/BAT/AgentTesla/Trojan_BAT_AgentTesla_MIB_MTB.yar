
rule Trojan_BAT_AgentTesla_MIB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 16 06 07 08 09 28 90 01 0e a2 28 90 01 09 13 04 11 04 72 90 01 09 13 05 11 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}