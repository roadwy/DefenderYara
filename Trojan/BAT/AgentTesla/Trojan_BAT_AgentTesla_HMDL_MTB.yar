
rule Trojan_BAT_AgentTesla_HMDL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HMDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 08 58 9e 08 17 58 0c 08 20 90 01 03 01 32 90 00 } //01 00 
		$a_01_1 = {24 34 62 36 65 37 38 62 35 2d 37 61 63 35 2d 37 61 38 61 2d 32 35 62 38 2d 33 63 35 62 37 31 38 63 38 35 61 32 } //01 00 
		$a_01_2 = {74 69 6d 61 74 65 20 53 79 73 74 65 6d 20 50 61 63 6b 36 34 20 62 79 20 41 78 69 72 74 53 6f 66 74 } //00 00 
	condition:
		any of ($a_*)
 
}