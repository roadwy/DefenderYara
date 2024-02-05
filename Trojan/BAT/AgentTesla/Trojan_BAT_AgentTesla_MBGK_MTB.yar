
rule Trojan_BAT_AgentTesla_MBGK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 06 07 6f 99 00 00 0a 17 73 75 00 00 0a 25 02 16 02 8e 69 6f 9a 00 00 0a } //01 00 
		$a_01_1 = {36 62 32 31 62 35 37 35 2d 36 65 34 33 2d 34 39 39 65 2d 38 31 66 38 2d 34 38 64 33 39 31 33 39 35 30 61 65 } //01 00 
		$a_01_2 = {4a 4a 6a 55 68 38 37 37 } //00 00 
	condition:
		any of ($a_*)
 
}