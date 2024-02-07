
rule Trojan_BAT_AgentTesla_LQI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 05 2b 35 00 02 09 11 04 11 05 28 90 01 03 06 13 07 11 06 13 09 11 09 13 08 11 08 1f 17 2e 02 2b 02 2b 0e 08 07 02 11 07 28 90 01 03 06 d2 9c 2b 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0a 11 0a 2d 90 00 } //01 00 
		$a_01_1 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //00 00  ColorTranslator
	condition:
		any of ($a_*)
 
}