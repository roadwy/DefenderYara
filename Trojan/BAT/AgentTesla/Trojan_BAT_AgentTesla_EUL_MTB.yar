
rule Trojan_BAT_AgentTesla_EUL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 0b 00 00 0a 0a 03 8e 69 0b 2b 0b 00 06 07 03 07 91 2b 18 00 2b 0b 07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e0 6f 90 01 03 0a 2b e1 06 6f 90 01 03 0a 28 90 01 03 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EUL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 72 00 00 09 69 00 6e 00 67 00 31 } //01 00 
		$a_01_1 = {86 06 45 00 86 06 45 00 86 06 45 00 86 06 45 00 86 06 } //01 00 
		$a_01_2 = {42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 } //01 00 
		$a_01_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00 
		$a_01_4 = {00 44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 00 } //01 00 
		$a_01_5 = {00 44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}