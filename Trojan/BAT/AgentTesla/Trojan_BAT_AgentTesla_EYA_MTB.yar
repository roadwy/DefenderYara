
rule Trojan_BAT_AgentTesla_EYA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 1a 5a 90 01 05 0b 06 16 07 16 07 8e 69 90 01 05 00 07 90 00 } //01 00 
		$a_01_1 = {4a 00 75 00 73 00 74 00 69 00 6e 00 20 00 54 00 69 00 6d 00 62 00 65 00 72 00 6c 00 61 00 6b 00 65 00 } //01 00  Justin Timberlake
		$a_01_2 = {67 00 65 00 74 00 5f 00 43 00 68 00 61 00 72 00 73 00 } //01 00  get_Chars
		$a_01_3 = {67 00 65 00 74 00 5f 00 4c 00 65 00 6e 00 67 00 74 00 68 00 } //01 00  get_Length
		$a_01_4 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //01 00  FromBase64String
		$a_01_5 = {47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //01 00  GetString
		$a_01_6 = {44 00 65 00 63 00 72 00 79 00 70 00 74 00 } //00 00  Decrypt
	condition:
		any of ($a_*)
 
}