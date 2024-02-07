
rule Trojan_BAT_AgentTesla_DRQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 22 00 08 09 11 04 28 90 01 03 06 13 07 11 07 28 90 01 03 0a 13 08 07 06 11 08 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 09 11 09 2d d3 06 17 58 0a 00 09 17 58 0d 90 00 } //01 00 
		$a_01_1 = {00 47 65 74 50 69 78 65 6c 00 } //01 00  䜀瑥楐數l
		$a_01_2 = {00 54 6f 57 69 6e 33 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_DRQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 26 00 08 09 11 04 28 90 01 03 06 13 06 11 06 28 90 01 03 0a 13 07 07 11 07 d2 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d cf 06 17 58 0a 00 09 17 58 0d 90 00 } //0a 00 
		$a_03_1 = {16 0c 2b 1f 11 05 07 08 28 90 01 03 06 13 06 11 06 28 90 01 03 0a 13 07 11 04 09 11 07 d2 9c 08 17 58 0c 08 17 fe 04 13 08 11 08 2d d7 09 17 58 0d 07 17 58 0b 90 00 } //01 00 
		$a_01_2 = {00 54 6f 57 69 6e 33 32 00 } //01 00 
		$a_01_3 = {00 47 65 74 50 69 78 65 6c 00 } //00 00  䜀瑥楐數l
	condition:
		any of ($a_*)
 
}