
rule Trojan_BAT_AgentTesla_NLA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 17 11 09 28 89 00 00 06 11 0d 20 90 01 03 4f 5a 20 13 20 04 f7 61 2b cb 90 00 } //01 00 
		$a_01_1 = {50 72 6f 67 72 61 6d 49 6e 73 74 61 6c 6c 65 72 2e 49 6e 74 65 72 66 61 63 65 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NLA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {12 02 22 00 00 61 43 11 00 58 6c 28 90 01 03 0a b7 28 90 01 03 0a 38 90 01 03 ff 02 6f 90 01 03 06 02 7b 90 01 03 04 6c 02 7b 90 01 03 04 6c 5b 28 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {41 75 6e 65 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NLA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 90 01 03 0a 20 90 01 03 00 da 13 05 11 05 28 90 01 03 0a 28 90 01 03 0a 13 06 07 11 06 28 90 01 03 0a 0b 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 07 11 07 2d b9 07 0a 06 2a 90 00 } //01 00 
		$a_01_1 = {24 64 64 63 31 62 39 30 30 2d 34 31 32 38 2d 34 34 63 30 2d 39 39 34 36 2d 36 37 30 33 66 34 66 64 39 33 64 } //01 00 
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}