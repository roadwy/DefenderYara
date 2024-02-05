
rule Trojan_BAT_AgentTesla_MBHU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {1a 58 4a 07 8e 69 5d 91 61 28 90 01 01 00 00 06 03 06 1a 58 4a 1b 58 1a 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBHU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 00 35 00 4b 00 34 00 48 00 35 00 35 00 48 00 44 00 35 00 41 00 50 00 34 00 35 00 38 00 46 00 46 00 34 00 38 00 35 00 34 00 38 00 } //01 00 
		$a_01_1 = {44 00 6f 00 64 00 67 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}