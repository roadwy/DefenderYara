
rule Trojan_BAT_AgentTesla_PTAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 73 13 00 00 0a 7d 0a 00 00 04 06 28 90 01 01 00 00 0a 00 72 01 00 00 70 28 90 01 01 00 00 0a 00 28 16 00 00 0a 0b 07 2c 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}