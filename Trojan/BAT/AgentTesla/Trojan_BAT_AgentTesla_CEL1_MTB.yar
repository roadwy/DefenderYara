
rule Trojan_BAT_AgentTesla_CEL1_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CEL1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {16 09 8e 69 6f 90 01 03 0a 26 28 90 01 03 0a 09 6f 90 01 03 0a 20 90 01 04 28 90 01 03 06 7e 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a 0a de 0a 90 09 0f 00 08 6f 90 01 03 0a d4 8d 90 01 03 01 0d 08 09 90 00 } //01 00 
		$a_81_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //01 00  GetManifestResourceStream
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 } //00 00  GetString
	condition:
		any of ($a_*)
 
}