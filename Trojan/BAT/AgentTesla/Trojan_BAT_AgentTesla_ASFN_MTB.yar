
rule Trojan_BAT_AgentTesla_ASFN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 00 0a 02 73 90 01 01 00 00 0a 7d 90 01 01 00 00 04 06 28 90 01 01 00 00 0a 00 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 00 28 90 01 01 00 00 0a 0b 07 2c 15 90 00 } //01 00 
		$a_01_1 = {47 00 f6 00 6e 00 64 00 65 00 72 00 20 00 77 00 61 00 6c 00 74 } //00 00 
	condition:
		any of ($a_*)
 
}