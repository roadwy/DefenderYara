
rule Trojan_BAT_Kryptik_PSA_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.PSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 55 a2 0b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 68 00 00 00 70 07 00 00 76 00 00 00 87 37 00 00 91 00 00 00 b8 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_2 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 43 41 50 49 2b 43 52 59 50 54 5f 41 4c 47 4f 52 49 54 48 4d 5f 49 44 45 4e 54 49 46 49 45 52 32 } //01 00  System.Security.Cryptography.CAPI+CRYPT_ALGORITHM_IDENTIFIER2
		$a_01_3 = {47 65 74 50 72 6f 63 65 73 73 42 79 49 64 } //01 00  GetProcessById
		$a_01_4 = {57 72 69 74 65 4c 69 6e 65 } //00 00  WriteLine
	condition:
		any of ($a_*)
 
}