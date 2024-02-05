
rule Trojan_BAT_AgentTesla_SPY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 8d bc 00 00 01 0a 06 16 d0 0b 00 00 1b 28 90 01 03 0a a2 06 28 90 01 03 0a 14 17 8d 16 00 00 01 0b 07 16 02 a2 07 6f 90 01 03 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}