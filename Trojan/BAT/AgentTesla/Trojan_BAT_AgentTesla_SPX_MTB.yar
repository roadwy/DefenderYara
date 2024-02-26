
rule Trojan_BAT_AgentTesla_SPX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 04 07 8e 69 5d 13 07 11 04 08 6f 90 01 03 0a 5d 13 08 07 11 07 91 13 09 08 11 08 6f 90 01 03 0a 13 0a 02 07 11 04 28 90 01 03 06 13 0b 02 11 09 11 0a 11 0b 28 90 01 03 06 13 0c 07 11 07 02 11 0c 28 90 01 03 06 9c 11 04 17 59 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}