
rule Trojan_BAT_AgentTesla_PTHY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 08 15 2c ed 28 90 01 01 00 00 0a 06 28 90 01 01 00 00 0a 2b 15 02 16 25 2d 6a 2f 08 16 28 90 01 01 00 00 0a 2b 06 16 28 90 01 01 00 00 0a 06 28 90 01 01 00 00 0a 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}