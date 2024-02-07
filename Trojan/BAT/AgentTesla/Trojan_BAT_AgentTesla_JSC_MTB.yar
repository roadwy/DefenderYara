
rule Trojan_BAT_AgentTesla_JSC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 06 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 00 07 06 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 00 07 6f 90 01 03 0a 02 16 02 8e 69 6f 90 00 } //01 00 
		$a_01_1 = {24 34 30 64 34 31 64 62 65 2d 35 34 65 36 2d 34 38 62 31 2d 61 63 64 39 2d 61 38 63 33 31 34 36 66 35 65 39 36 } //01 00  $40d41dbe-54e6-48b1-acd9-a8c3146f5e96
		$a_01_2 = {5f 58 5f 58 30 46 54 5f 46 54 32 } //00 00  _X_X0FT_FT2
	condition:
		any of ($a_*)
 
}