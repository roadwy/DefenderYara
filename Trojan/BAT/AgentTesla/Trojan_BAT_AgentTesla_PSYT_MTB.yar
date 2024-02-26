
rule Trojan_BAT_AgentTesla_PSYT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 2e 40 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 06 20 03 40 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 06 6f 03 00 00 0a 13 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}