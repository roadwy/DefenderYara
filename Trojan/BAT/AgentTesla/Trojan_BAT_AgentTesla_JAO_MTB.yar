
rule Trojan_BAT_AgentTesla_JAO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0a de 1c 26 03 72 90 01 03 70 7e 90 01 03 0a 6f 90 01 03 0a 10 01 03 28 90 01 03 0a 0a de 00 90 00 } //0a 00 
		$a_02_1 = {0a 26 06 28 90 01 03 06 28 90 01 03 06 06 2e 17 72 90 01 03 70 06 28 90 01 03 06 06 8c 90 01 03 01 28 90 01 03 0a 2a 06 17 58 0a 06 1f 64 32 c7 90 00 } //01 00 
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_81_4 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_81_5 = {44 65 63 6f 64 65 } //01 00  Decode
		$a_81_6 = {45 6e 63 6f 64 65 } //01 00  Encode
		$a_81_7 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //00 00  GetExecutingAssembly
	condition:
		any of ($a_*)
 
}