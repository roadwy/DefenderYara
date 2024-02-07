
rule Trojan_BAT_AgentTesla_ADA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 06 09 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a d2 6f 90 01 03 0a 00 00 09 17 58 0d 09 06 6f 90 01 03 0a 18 5b 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_2 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //01 00  CreateInstance
		$a_01_3 = {54 6f 49 6e 74 33 32 } //01 00  ToInt32
		$a_01_4 = {53 75 62 73 74 72 69 6e 67 } //01 00  Substring
		$a_01_5 = {50 61 72 61 6d 58 41 72 72 61 79 } //01 00  ParamXArray
		$a_01_6 = {50 61 72 61 6d 58 47 72 6f 75 70 } //00 00  ParamXGroup
	condition:
		any of ($a_*)
 
}