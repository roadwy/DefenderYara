
rule Trojan_BAT_AgentTesla_PSOE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0b 28 7e 00 00 06 17 8d 39 00 00 01 25 16 1f 5c 9d 6f 90 01 03 0a 28 0d 00 00 2b 0c 1b 13 08 38 7c ff ff ff 28 90 01 03 0a 6f 90 01 03 0a 0d 08 14 14 1e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}