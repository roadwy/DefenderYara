
rule Trojan_BAT_AgentTesla_PSAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e d7 00 00 04 d0 07 00 00 1b 28 2b 90 01 03 6f 75 90 01 03 0d 09 2c 16 72 41 39 02 70 16 8d 87 00 00 01 28 76 90 01 03 73 77 90 01 03 7a 00 00 2b 0c 00 73 78 90 01 03 80 d7 00 00 04 00 7e d7 00 00 04 d0 07 00 00 1b 28 2b 90 01 03 14 6f 79 90 01 03 00 00 28 01 00 00 2b 0a de 74 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {47 65 74 48 61 73 68 43 6f 64 65 } //01 00  GetHashCode
		$a_01_3 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //00 00  ContainsKey
	condition:
		any of ($a_*)
 
}