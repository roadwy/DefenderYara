
rule Trojan_BAT_AgentTesla_PSWY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSWY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 72 4f 00 00 70 02 28 90 01 01 00 00 0a 0b 07 28 90 01 01 00 00 0a 75 15 00 00 01 0c 08 72 2e 01 00 70 6f 90 01 01 00 00 0a 00 08 6f 90 01 01 00 00 0a 0d 09 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 73 26 00 00 0a 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}