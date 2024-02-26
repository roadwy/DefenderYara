
rule Trojan_BAT_AgentTesla_KAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {08 11 0a 11 09 6f 6c 00 00 0a 13 0b 16 13 0c 11 05 11 08 9a 72 b3 02 00 70 28 6d 00 00 0a 2c 0b 12 0b 28 6e 00 00 0a 13 0c 2b 36 11 05 11 08 9a 72 b7 02 00 70 28 6d 00 00 0a 2c 0b 12 0b 28 6f 00 00 0a 13 0c 2b 1a 11 05 11 08 9a 72 bb 02 00 70 28 6d 00 00 0a 2c 09 12 0b 28 70 00 00 0a 13 0c 07 11 0c 6f 71 00 00 0a 11 0a 17 58 13 0a 11 0a 09 32 8c } //00 00 
	condition:
		any of ($a_*)
 
}