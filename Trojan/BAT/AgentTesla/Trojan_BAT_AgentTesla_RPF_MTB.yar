
rule Trojan_BAT_AgentTesla_RPF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 02 8e 69 0b 2b 0a 00 06 02 07 91 2b 18 00 2b 0b 07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 00 66 00 6a 00 68 00 47 00 65 00 74 00 42 00 79 00 4f 00 66 00 6a 00 68 00 74 00 65 00 41 00 72 00 72 00 4f 00 66 00 6a 00 68 00 61 00 79 00 41 00 73 00 79 00 4f 00 66 00 6a 00 68 00 6e 00 63 00 } //01 00 
		$a_01_1 = {31 00 38 00 35 00 2e 00 32 00 32 00 32 00 2e 00 35 00 38 00 2e 00 35 00 36 00 } //01 00 
		$a_01_2 = {42 00 75 00 66 00 67 00 6a 00 2e 00 70 00 6e 00 67 00 } //01 00 
		$a_01_3 = {53 00 6c 00 65 00 65 00 70 00 } //01 00 
		$a_01_4 = {47 00 79 00 65 00 63 00 73 00 63 00 6e 00 68 00 6b 00 62 00 79 00 76 00 6a 00 62 00 67 00 76 00 72 00 66 00 } //00 00 
	condition:
		any of ($a_*)
 
}