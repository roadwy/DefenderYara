
rule Trojan_BAT_AgentTesla_ASAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0b 07 0c 02 08 1f f6 28 90 01 01 00 00 06 17 8d 90 01 01 00 00 01 25 16 1f 7e 9d 6f 90 01 01 00 00 0a 0d 73 90 01 01 00 00 0a 13 04 09 8e 69 17 da 13 08 16 13 09 2b 1b 11 04 11 09 09 11 09 9a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 09 17 d6 13 09 11 09 11 08 31 df 90 00 } //01 00 
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 47 00 69 00 61 00 79 00 2e 00 43 00 43 00 4d 00 } //00 00 
	condition:
		any of ($a_*)
 
}