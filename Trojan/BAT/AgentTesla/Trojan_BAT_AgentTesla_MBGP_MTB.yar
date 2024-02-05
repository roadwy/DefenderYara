
rule Trojan_BAT_AgentTesla_MBGP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 1f 2c 9d 6f 90 01 01 01 00 0a 16 9a 73 90 01 01 01 00 0a 2a 90 00 } //01 00 
		$a_01_1 = {65 65 2d 37 33 66 62 36 36 37 38 63 64 62 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBGP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 2d 30 33 2d 52 2d 45 32 2d 52 2d 30 33 2d 52 2d 45 32 2d 52 2d 30 33 2d 52 2d 45 32 2d 52 2d 31 33 2d 52 2d 52 2d 52 2d 45 36 2d 52 2d 46 36 2d 52 2d 39 36 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBGP_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 07 11 06 11 21 9a 1f 10 28 90 01 01 00 00 0a b4 6f 90 01 01 00 00 0a 00 11 21 17 d6 13 21 11 21 11 20 31 df 90 00 } //01 00 
		$a_01_1 = {4c 00 6f 00 2d 00 61 00 64 00 20 00 01 03 2d 00 01 13 51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 00 11 47 00 69 00 61 00 79 } //00 00 
	condition:
		any of ($a_*)
 
}