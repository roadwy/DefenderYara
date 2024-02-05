
rule Trojan_BAT_AgentTesla_SPW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 07 20 8b 18 fe f1 5a 20 40 d2 f6 f6 61 38 b7 fe ff ff 28 90 01 03 0a 7e 01 00 00 04 02 08 6f 90 01 03 0a 28 90 01 03 0a a5 01 00 00 1b 0b 11 07 20 41 68 4f 51 5a 20 e0 6d 88 f0 61 38 88 fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_SPW_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 73 0e 00 00 0a 0d 09 17 6f 90 01 03 0a 09 18 6f 90 01 03 0a 09 0c 08 06 06 1f 10 28 90 01 03 06 6f 90 01 03 0a 13 04 73 12 00 00 0a 13 05 90 00 } //01 00 
		$a_01_1 = {59 00 55 00 43 00 67 00 31 00 66 00 42 00 7a 00 33 00 6b 00 35 00 4e 00 31 00 45 00 6b 00 64 00 50 00 75 00 37 00 4a 00 6a 00 55 00 38 00 79 00 33 00 64 00 6f 00 77 00 56 00 51 00 36 00 7a 00 } //00 00 
	condition:
		any of ($a_*)
 
}