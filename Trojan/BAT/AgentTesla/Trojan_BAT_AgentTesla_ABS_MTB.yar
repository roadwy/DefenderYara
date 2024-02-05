
rule Trojan_BAT_AgentTesla_ABS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 05 11 09 8f 90 01 03 01 25 47 11 08 61 d2 52 11 05 11 09 91 13 08 00 11 09 17 58 13 09 11 09 11 05 8e 69 fe 04 13 0a 11 0a 2d d3 90 00 } //01 00 
		$a_01_1 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_01_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {95 e0 11 0b 13 0b 95 2d 03 16 2b 01 17 17 59 7e 1d 00 00 04 19 9a 20 f4 03 00 00 95 5f 7e 1d 00 00 04 19 06 0a 9a 20 73 02 00 00 95 61 58 81 05 00 00 01 } //02 00 
		$a_01_1 = {58 7e 0e 00 00 04 35 03 16 2b 01 17 17 59 7e 19 00 00 04 19 9a 20 13 05 00 00 95 5f 7e 19 00 00 04 19 9a 20 16 05 00 00 95 61 58 81 06 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABS_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63 00 00 } //01 00 
		$a_81_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //01 00 
		$a_81_2 = {56 4d 4e 56 49 4a 53 46 } //01 00 
		$a_81_3 = {40 44 46 53 46 45 48 47 48 48 44 54 40 66 73 65 33 } //01 00 
		$a_81_4 = {39 39 39 39 53 39 39 39 39 79 39 39 39 73 39 74 39 65 39 6d 39 } //01 00 
		$a_81_5 = {39 39 39 39 39 39 39 39 39 52 39 65 39 66 39 6c 39 65 39 63 39 74 39 69 39 6f 39 6e 39 } //01 00 
		$a_81_6 = {39 39 39 39 39 39 39 39 39 39 39 39 39 39 39 39 39 39 39 41 73 39 73 39 65 39 6d 39 62 39 6c 39 79 39 } //01 00 
		$a_81_7 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}