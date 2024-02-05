
rule Trojan_BAT_AgentTesla_PSGG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 cb 00 00 0a 13 04 11 04 17 6f 90 01 03 0a 11 04 17 6f 90 01 03 0a 11 04 0b 07 03 06 6f 90 01 03 0a 0c 28 90 01 03 0a 08 02 16 02 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 0d 09 1f 10 6f 90 01 03 0a 13 05 de 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}