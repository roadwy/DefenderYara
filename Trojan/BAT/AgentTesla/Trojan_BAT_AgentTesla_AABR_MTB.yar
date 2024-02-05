
rule Trojan_BAT_AgentTesla_AABR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 11 0b 11 0a 6f 90 01 01 00 00 0a 13 0c 16 13 0d 11 05 11 09 9a 13 0f 11 0f 13 0e 11 0e 72 e5 09 00 70 28 90 01 01 00 00 0a 2d 1e 11 0e 72 e9 09 00 70 28 90 01 01 00 00 0a 2d 1b 11 0e 72 ed 09 00 70 28 90 01 01 00 00 0a 2d 18 2b 21 12 0c 28 90 01 01 00 00 0a 13 0d 2b 16 12 0c 28 90 01 01 00 00 0a 13 0d 2b 0b 12 0c 28 90 01 01 00 00 0a 13 0d 2b 00 07 11 0d 6f 90 01 01 00 00 0a 00 00 11 0b 17 58 13 0b 11 0b 09 fe 04 13 10 11 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}