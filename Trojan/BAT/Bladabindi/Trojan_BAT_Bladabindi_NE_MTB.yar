
rule Trojan_BAT_Bladabindi_NE_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 0c 25 17 58 13 0c 93 11 90 01 01 61 60 13 07 11 16 90 00 } //05 00 
		$a_03_1 = {11 0c 25 17 58 13 0c 93 11 90 01 01 61 60 13 07 11 17 90 00 } //05 00 
		$a_03_2 = {11 0c 25 17 58 13 0c 93 11 90 01 01 61 60 13 07 11 1a 90 00 } //05 00 
		$a_03_3 = {11 0c 25 17 58 13 0c 93 11 90 01 01 61 60 13 07 11 1d 90 00 } //05 00 
		$a_03_4 = {11 0c 25 17 58 13 0c 93 11 90 01 01 61 60 13 07 11 22 90 00 } //05 00 
		$a_03_5 = {11 0c 25 17 58 13 0c 93 11 90 01 01 61 60 13 07 11 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Bladabindi_NE_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e 90 01 01 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 7b 02 00 06 58 54 90 00 } //01 00 
		$a_81_1 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_81_2 = {52 65 67 69 73 74 72 79 4b 65 79 50 65 72 6d 69 73 73 69 6f 6e 43 68 65 63 6b } //01 00  RegistryKeyPermissionCheck
		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_81_4 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_81_5 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //00 00  System.Security.Cryptography
	condition:
		any of ($a_*)
 
}