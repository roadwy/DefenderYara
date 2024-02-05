
rule Trojan_BAT_AgentTesla_PSXP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {fe 0c 03 00 28 a3 00 00 0a 28 17 02 00 06 fe 0e 04 00 73 6c 01 00 06 fe 0e 05 00 fe 0c 04 00 6f 13 02 00 06 6f 0c 01 00 0a fe 0e 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}