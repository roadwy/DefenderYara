
rule Trojan_BAT_AgentTesla_NKG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {00 00 06 0c 08 20 90 01 04 28 90 01 03 0a fe 04 0d 09 2c 15 06 20 90 01 04 d6 0a 07 16 06 17 d6 8d 90 01 03 01 a2 2b d6 90 00 } //0a 00 
		$a_03_1 = {00 07 16 fe 02 16 fe 01 0c 08 2c 1c 07 17 d6 0b 06 72 0e 05 00 70 28 90 01 03 0a 8c 90 01 03 01 6f 90 01 03 0a 00 2b d8 90 00 } //01 00 
		$a_01_2 = {54 6f 49 6e 74 33 32 } //01 00 
		$a_01_3 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00 
		$a_01_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00 
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}