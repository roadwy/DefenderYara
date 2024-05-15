
rule Trojan_BAT_Heracles_AHE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 19 15 28 90 01 01 00 00 0a 00 17 28 90 01 01 00 00 0a b7 28 90 01 01 00 00 0a 0a 17 12 00 15 6a 16 28 90 01 01 00 00 0a 00 17 8d 4d 00 00 01 0d 09 16 17 9e 09 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHE_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0c 07 16 08 6e 28 18 00 00 0a 07 8e 69 28 19 00 00 0a 7e 1a 00 00 0a 26 16 0d 7e 1a 00 00 0a 13 04 16 16 08 11 04 16 12 03 28 } //01 00 
		$a_01_1 = {73 68 6c 6c 63 72 79 70 74 72 75 6e 6e } //00 00  shllcryptrunn
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHE_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 18 02 03 07 28 90 01 03 06 0a 06 2d 08 07 80 90 01 01 04 00 04 14 2a 07 17 58 0b 07 7e 90 01 01 04 00 04 8e 69 32 de 02 14 51 90 00 } //01 00 
		$a_01_1 = {4e 00 69 00 63 00 65 00 48 00 61 00 73 00 68 00 51 00 75 00 69 00 63 00 6b 00 4d 00 69 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  NiceHashQuickMiner.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHE_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0b 07 8e 69 8d 10 00 00 01 0c 16 0d 38 29 00 00 00 07 09 91 06 59 20 00 01 00 00 5d 13 04 11 04 16 3c 0a 00 00 00 11 04 20 00 01 00 00 58 13 04 08 09 11 04 d2 9c 09 17 58 0d 09 07 8e 69 32 d1 } //01 00 
		$a_03_1 = {0b 06 8e 69 07 8e 69 59 8d 90 01 01 00 00 01 0c 06 07 07 8e 69 28 90 01 01 00 00 0a 06 07 8e 69 08 16 08 8e 69 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0d 09 20 80 00 00 00 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHE_MTB_5{
	meta:
		description = "Trojan:BAT/Heracles.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1e 02 06 02 06 91 03 06 03 28 90 01 01 00 00 06 25 26 5d 28 90 01 01 01 00 06 25 26 61 d2 9c 06 17 58 0a 06 02 28 90 01 01 01 00 06 25 26 69 32 d6 90 00 } //01 00 
		$a_01_1 = {72 61 74 54 65 73 74 73 2e 70 64 62 } //01 00  ratTests.pdb
		$a_01_2 = {76 00 4d 00 65 00 4a 00 4c 00 34 00 79 00 74 00 4f 00 4a 00 } //01 00  vMeJL4ytOJ
		$a_01_3 = {61 35 31 32 37 35 36 66 2d 66 39 30 39 2d 34 33 62 38 2d 61 35 35 38 2d 32 33 63 32 62 65 31 32 37 64 32 33 } //00 00  a512756f-f909-43b8-a558-23c2be127d23
	condition:
		any of ($a_*)
 
}