
rule Trojan_BAT_AgentTesla_MBIG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 07 6f 90 01 01 00 00 0a 17 73 7a 00 00 0a 0c 08 02 16 02 8e 69 6f cc 00 00 0a 08 6f 90 01 01 00 00 0a 06 28 90 01 01 00 00 06 0d 09 2a 90 00 } //01 00 
		$a_01_1 = {24 61 37 61 37 61 32 64 31 2d 64 66 30 30 2d 34 62 31 35 2d 62 32 63 64 2d 31 63 61 62 39 39 38 36 34 62 37 66 } //01 00 
		$a_01_2 = {44 6f 72 6d 41 6e 64 4d 65 61 6c 50 6c 61 6e 43 61 6c 63 75 6c 61 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}