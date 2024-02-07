
rule Trojan_BAT_AgentTesla_ANA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ANA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 fe 01 13 08 11 08 2c 6f 00 16 13 09 16 13 0a 2b 32 00 09 7b 03 00 00 04 11 0a 6f 90 01 03 0a 7b 1c 00 00 04 11 07 7b 1c 00 00 04 28 90 01 03 0a 13 0b 11 0b 2c 06 00 11 0a 13 09 00 00 11 0a 17 58 13 0a 11 0a 09 7b 03 00 00 04 6f 90 01 03 0a fe 04 13 0c 11 0c 2d b9 90 00 } //01 00 
		$a_01_1 = {61 00 68 00 70 00 5f 00 6d 00 65 00 74 00 6f 00 64 00 61 00 5f 00 70 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 } //00 00  ahp_metoda_projekt
	condition:
		any of ($a_*)
 
}