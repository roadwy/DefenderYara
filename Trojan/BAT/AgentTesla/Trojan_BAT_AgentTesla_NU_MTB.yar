
rule Trojan_BAT_AgentTesla_NU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 04 28 90 01 03 06 03 04 17 58 20 00 3a 00 00 5d 91 59 06 58 06 5d 0b 03 04 20 00 3a 00 00 5d 07 d2 9c 03 0c 2b 00 90 00 } //01 00 
		$a_01_1 = {35 00 50 00 48 00 34 00 37 00 35 00 4e 00 47 00 42 00 38 00 59 00 45 00 46 00 39 00 34 00 34 00 5a 00 46 00 43 00 49 00 35 00 41 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 6f 90 02 04 1f 90 01 01 28 90 02 04 28 90 02 04 6f 90 02 04 26 09 18 d6 0d 09 08 31 90 00 } //01 00 
		$a_02_1 = {91 08 61 07 11 90 01 01 91 61 b4 9c 11 90 02 02 6f 90 02 04 17 da fe 90 02 09 2c 90 01 01 16 13 90 02 02 2b 90 02 02 11 90 01 01 17 d6 13 90 02 02 11 90 01 01 17 d6 13 90 01 01 11 90 01 01 11 90 01 01 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NU_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 06 08 11 04 6f 90 01 03 0a 13 05 08 11 05 58 0c 11 04 11 05 59 13 04 11 04 16 3d 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {53 70 66 53 65 74 4b 65 79 } //01 00 
		$a_01_2 = {53 00 70 00 6f 00 6f 00 66 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00 
		$a_01_3 = {48 77 69 64 45 64 69 74 49 74 65 6d } //00 00 
	condition:
		any of ($a_*)
 
}