
rule Trojan_BAT_AgentTesla_GAGA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 72 90 01 03 70 28 90 01 03 06 74 90 01 03 1b 6f 90 01 03 0a 0c 73 90 01 03 0a 0d 09 08 6f 90 01 03 0a 00 09 18 6f 90 01 03 0a 00 09 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 13 04 11 04 02 28 90 01 03 06 28 90 01 03 06 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_3 = {46 00 52 00 35 00 37 00 41 00 48 00 51 00 59 00 38 00 44 00 42 00 46 00 42 00 41 00 35 00 34 00 44 00 47 00 34 00 35 00 59 00 35 00 } //01 00  FR57AHQY8DBFBA54DG45Y5
		$a_01_4 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_01_5 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}