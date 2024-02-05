
rule Trojan_BAT_AgentTesla_MBCJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 11 05 08 11 05 91 07 11 05 07 8e 69 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d d9 } //01 00 
		$a_01_1 = {62 00 62 00 63 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBCJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 00 80 01 00 8d 90 01 01 00 00 01 0b 06 72 73 02 00 70 6f 90 01 01 00 00 0a 74 90 01 01 00 00 1b 16 07 16 20 00 c0 00 00 28 90 01 01 00 00 0a 00 06 72 79 02 00 70 6f 90 01 01 00 00 0a 74 90 01 01 00 00 1b 16 07 20 00 c0 00 00 20 00 c0 00 00 28 90 01 01 00 00 0a 00 d0 90 01 01 00 00 01 28 5a 00 00 0a 72 7f 02 00 70 20 00 01 00 00 14 14 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBCJ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {18 da 13 06 16 13 07 2b 23 07 08 06 11 07 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a b4 6f 90 01 01 00 00 0a 00 08 17 d6 0c 11 07 18 d6 13 07 11 07 11 06 31 d7 90 00 } //01 00 
		$a_01_1 = {34 00 30 00 32 00 30 00 30 00 35 00 32 00 46 00 46 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 43 00 36 00 43 00 36 00 34 00 36 00 45 00 32 00 35 00 36 00 35 00 36 00 32 00 37 00 46 00 36 00 33 00 36 00 33 00 37 00 44 } //00 00 
	condition:
		any of ($a_*)
 
}