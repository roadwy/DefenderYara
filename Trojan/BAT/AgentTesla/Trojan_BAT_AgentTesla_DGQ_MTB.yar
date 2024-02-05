
rule Trojan_BAT_AgentTesla_DGQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 6f 90 01 03 0a 13 05 08 09 11 04 6f 90 01 03 0a 13 06 11 06 28 90 01 03 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 08 6f 90 01 03 0a 13 09 12 09 28 90 01 03 0a fe 04 13 08 11 08 2d ba 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //01 00 
		$a_01_2 = {54 6f 57 69 6e 33 32 } //01 00 
		$a_01_3 = {47 65 74 54 79 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_DGQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 30 35 39 39 38 61 34 63 2d 31 37 35 37 2d 34 34 65 35 2d 61 64 62 39 2d 32 34 34 36 36 36 36 32 33 37 34 36 } //01 00 
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00 
		$a_01_3 = {52 00 65 00 61 00 64 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //01 00 
		$a_01_4 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //01 00 
		$a_01_5 = {53 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}