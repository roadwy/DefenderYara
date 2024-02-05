
rule Trojan_BAT_AgentTesla_ZQEA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ZQEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 07 11 09 6f 90 01 03 0a 13 0a 11 0a 16 16 16 16 28 90 01 03 0a 28 90 01 03 0a 13 0b 11 0b 2c 2c 00 08 12 0a 28 90 01 03 0a 6f 90 01 03 0a 00 08 12 0a 28 90 01 03 0a 6f 90 01 03 0a 00 08 12 0a 28 90 01 03 0a 6f 90 01 03 0a 00 00 00 11 09 17 d6 13 09 11 09 11 08 fe 02 16 fe 01 13 0c 11 0c 2d 9b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}