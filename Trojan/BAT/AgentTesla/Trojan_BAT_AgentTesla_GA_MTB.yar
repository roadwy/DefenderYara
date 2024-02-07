
rule Trojan_BAT_AgentTesla_GA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 07 11 04 9a 72 90 01 03 70 15 16 28 90 01 03 0a 16 9a 14 02 fe 06 c6 00 00 06 73 90 01 03 0a 6f 90 01 03 0a 07 11 04 9a 72 90 01 03 70 15 16 28 90 01 03 0a 17 9a 6f 90 01 03 0a 00 11 04 17 d6 13 04 11 04 09 31 ae 90 00 } //01 00 
		$a_81_1 = {43 72 69 74 69 63 61 6c 41 74 74 72 69 62 75 74 65 } //01 00  CriticalAttribute
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}