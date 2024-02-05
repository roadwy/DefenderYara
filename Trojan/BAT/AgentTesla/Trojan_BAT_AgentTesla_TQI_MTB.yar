
rule Trojan_BAT_AgentTesla_TQI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.TQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {00 02 09 11 05 6f 90 01 04 13 06 11 06 16 16 16 16 28 90 01 09 13 07 11 07 2c 2d 00 06 19 8d 90 01 04 25 16 12 06 28 90 01 04 9c 25 17 12 06 28 90 01 04 9c 25 18 12 06 28 90 01 04 9c 6f 90 01 04 00 00 00 11 05 17 d6 13 05 11 05 11 04 fe 02 16 fe 01 13 08 11 08 2d 9b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}