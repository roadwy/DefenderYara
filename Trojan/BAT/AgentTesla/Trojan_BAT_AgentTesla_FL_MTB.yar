
rule Trojan_BAT_AgentTesla_FL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0c 1e 8d 90 01 03 01 0d 08 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 13 04 11 04 16 09 16 1e 28 90 01 03 0a 00 07 09 6f 90 01 03 0a 00 07 18 6f 90 01 03 0a 00 07 6f 90 01 03 0a 03 16 03 8e 69 6f 90 01 03 0a 90 00 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_FL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 09 00 00 06 72 01 00 00 70 72 05 00 00 70 6f 90 01 03 0a 28 90 01 03 0a 72 0b 00 00 70 28 90 01 03 06 28 90 01 03 0a 0a 06 6f 90 01 03 0a 0b 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_2 = {4d 44 35 44 65 63 72 79 70 74 } //01 00  MD5Decrypt
		$a_81_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_4 = {4b 42 34 47 47 48 30 52 46 35 50 } //00 00  KB4GGH0RF5P
	condition:
		any of ($a_*)
 
}