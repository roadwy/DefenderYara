
rule Trojan_BAT_AgentTesla_JAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0a 16 0b 2b 22 06 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 6f 90 01 03 0a 26 07 17 58 0b 07 02 6f 90 01 03 0a 90 00 } //01 00 
		$a_81_1 = {00 73 74 72 69 6e 67 4b 65 79 00 47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 00 } //01 00 
		$a_81_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //01 00 
		$a_81_3 = {53 79 73 74 65 6d 53 65 72 76 69 63 65 4d 6f 64 65 6c 43 68 61 6e 6e 65 6c 73 } //01 00 
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}