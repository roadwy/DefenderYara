
rule Trojan_BAT_AgentTesla_EHA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 07 93 28 90 01 03 0a 1f 21 32 11 08 07 93 28 90 01 03 0a 1f 7e fe 02 16 fe 01 2b 01 16 0d 09 2c 16 00 08 07 1f 21 08 07 93 1f 0e 58 1f 5e 5d 58 28 90 01 03 0a 9d 00 00 07 17 58 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}