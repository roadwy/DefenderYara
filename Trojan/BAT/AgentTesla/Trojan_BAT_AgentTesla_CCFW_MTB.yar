
rule Trojan_BAT_AgentTesla_CCFW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CCFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 07 11 09 11 0e 11 0b 59 11 07 5d d2 9c 00 11 06 17 58 13 06 11 06 20 90 01 04 fe 04 13 0f 11 0f 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}