
rule Trojan_BAT_AgentTesla_RD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 0b 2b 27 08 06 07 6f 3e 00 00 0a 26 08 06 07 6f 3e 00 00 0a 13 05 11 05 28 3f 00 00 0a 13 06 11 04 09 11 06 d2 9c 07 17 58 0b 07 08 6f 40 00 00 0a fe 04 13 07 11 07 2d ca 09 17 58 0d 06 17 58 0a 06 08 6f 41 00 00 0a fe 04 13 08 11 08 2d af } //02 00 
		$a_01_1 = {28 43 00 00 0a 02 6f 44 00 00 0a 0a 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 0c 11 0d 9a 13 08 00 02 11 07 11 08 28 02 00 00 06 00 00 11 0d 17 58 13 0d 11 0d 11 0c 8e 69 fe 04 13 0e 11 0e 2d d8 } //01 00 
		$a_01_1 = {54 00 79 00 78 00 69 00 66 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_2 = {53 68 61 72 70 44 65 76 65 6c 6f 70 20 50 72 6f 6a 65 63 74 73 5c 54 79 78 69 66 5c 54 79 78 69 66 5c 6f 62 6a 5c 44 65 62 75 67 5c 54 79 78 69 66 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}