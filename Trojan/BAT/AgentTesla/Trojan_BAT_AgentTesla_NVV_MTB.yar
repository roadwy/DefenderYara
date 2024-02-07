
rule Trojan_BAT_AgentTesla_NVV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 07 06 9a 20 f0 00 00 00 06 5a 07 06 9a 7b 06 01 00 04 2d 04 1f 1b 2b 01 16 73 90 01 03 0a 6f 90 01 03 0a 07 06 9a 20 f0 00 00 00 90 00 } //01 00 
		$a_01_1 = {1f a2 0b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 fc 00 00 00 4a 00 00 00 1d 01 00 00 8e 01 00 00 53 01 00 00 12 00 00 00 3e 02 00 00 03 } //01 00 
		$a_01_2 = {39 65 30 33 2d 38 30 36 64 61 65 35 33 61 64 65 61 } //00 00  9e03-806dae53adea
	condition:
		any of ($a_*)
 
}