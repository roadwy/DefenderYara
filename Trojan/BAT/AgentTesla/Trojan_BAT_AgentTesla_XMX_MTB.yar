
rule Trojan_BAT_AgentTesla_XMX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.XMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 07 0c 08 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 0c 73 90 01 03 0a 0d 16 13 07 2b 1c 09 08 11 07 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 11 07 18 58 13 07 11 07 08 6f 90 01 03 0a 32 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}