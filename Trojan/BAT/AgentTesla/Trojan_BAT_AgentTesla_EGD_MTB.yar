
rule Trojan_BAT_AgentTesla_EGD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 08 23 00 00 00 00 00 00 10 40 28 90 01 03 0a b7 6f 90 01 03 0a 23 00 00 00 00 00 00 70 40 28 90 01 03 0a b7 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 00 08 18 d6 0c 90 00 } //01 00 
		$a_01_1 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EGD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 73 3a 2f 2f 90 01 07 20 64 69 76 6f 90 01 07 20 72 63 65 72 90 01 07 20 68 74 74 70 90 01 07 20 2e 63 6f 6d 90 01 07 20 61 64 69 6f 90 00 } //01 00 
		$a_01_1 = {22 00 73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 69 00 6e 00 66 00 6f 00 22 00 3a } //01 00 
		$a_01_2 = {22 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 5f 00 69 00 6e 00 66 00 6f 00 22 00 3a 00 20 00 22 } //00 00 
	condition:
		any of ($a_*)
 
}