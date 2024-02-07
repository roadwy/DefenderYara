
rule Trojan_BAT_AgentTesla_CDC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 16 74 00 00 0c 2b 13 00 72 90 01 03 70 07 08 28 90 01 03 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 90 00 } //01 00 
		$a_01_1 = {42 00 61 00 74 00 63 00 68 00 52 00 75 00 6e 00 6e 00 65 00 72 00 } //01 00  BatchRunner
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CDC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0b 06 07 16 07 8e 69 6f 90 01 03 0a 26 17 8d 90 01 03 01 25 16 07 28 90 01 03 06 28 90 01 03 06 a2 0c 72 90 01 03 70 28 90 01 03 0a 72 90 01 03 70 17 8d 90 01 03 01 25 16 d0 90 01 03 1b 28 90 01 03 0a a2 6f 90 01 03 0a 14 08 6f 90 01 03 0a 75 90 01 03 01 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}