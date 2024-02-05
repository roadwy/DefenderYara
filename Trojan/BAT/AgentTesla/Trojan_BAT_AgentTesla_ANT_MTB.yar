
rule Trojan_BAT_AgentTesla_ANT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ANT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 06 18 5b 8d 2c 00 00 01 0b 16 0c 2b 18 07 08 18 5b 03 08 18 6f 30 00 00 0a 1f 10 28 31 00 00 0a 9c 08 18 58 0c 08 06 32 e4 } //01 00 
		$a_03_1 = {20 c5 e1 01 00 28 90 01 03 0a 03 a5 34 00 00 01 18 33 02 de 05 de e9 26 de e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}