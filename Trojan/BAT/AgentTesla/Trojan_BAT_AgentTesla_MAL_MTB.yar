
rule Trojan_BAT_AgentTesla_MAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 13 07 08 9a 03 28 0b 00 00 06 0d 09 2c 02 09 2a 08 17 58 0c 08 07 8e 69 32 e7 14 2a } //05 00 
		$a_01_1 = {28 12 00 00 06 0a 28 18 00 00 0a 06 6f 19 00 00 0a 28 1a 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b de 03 26 de d9 07 2a } //01 00 
		$a_01_2 = {67 65 74 5f 6d 79 6f 6e } //01 00  get_myon
		$a_01_3 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}