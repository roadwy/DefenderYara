
rule Trojan_BAT_AgentTesla_NVW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 16 11 04 6f 90 01 01 00 00 0a 08 09 16 09 8e 69 6f 90 01 01 00 00 0a 25 13 04 16 30 e5 90 00 } //01 00 
		$a_01_1 = {54 00 77 00 6b 00 7a 00 69 00 64 00 62 00 74 00 66 00 2e 00 42 00 74 00 73 00 7a 00 61 00 6b 00 76 00 6c 00 63 00 } //01 00 
		$a_81_2 = {38 30 2e 36 36 2e 37 35 2e 32 35 2f 70 6c 2d 55 66 62 7a 79 61 72 6e 5f 55 73 62 71 68 61 65 65 2e 62 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}