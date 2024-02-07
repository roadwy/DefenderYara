
rule Trojan_BAT_AgentTesla_EKX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 04 08 09 6f 90 01 03 0a 13 0a 11 0a 16 16 16 16 28 90 01 03 0a 28 90 01 03 0a 13 0b 11 0b 2c 27 07 12 0a 28 90 01 03 0a 6f 90 01 03 0a 07 12 0a 28 90 01 03 0a 6f 90 01 03 0a 07 12 0a 28 90 01 03 0a 6f 90 01 03 0a 09 17 d6 0d 90 00 } //01 00 
		$a_01_1 = {00 47 65 74 50 69 78 65 6c 00 } //01 00  䜀瑥楐數l
		$a_01_2 = {00 46 72 6f 6d 41 72 67 62 00 } //00 00  䘀潲䅭杲b
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EKX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 07 9a 0c 00 00 08 6f 90 01 03 0a 0d 16 13 04 2b 2f 09 11 04 9a 13 05 00 11 05 6f 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 13 06 11 06 2c 0a 00 11 05 28 90 01 03 06 00 00 00 11 04 17 58 13 04 11 04 09 8e 69 90 00 } //01 00 
		$a_01_1 = {00 47 65 74 4d 65 74 68 6f 64 00 } //01 00 
		$a_01_2 = {00 47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 00 } //00 00  䜀瑥硅潰瑲摥祔数s
	condition:
		any of ($a_*)
 
}