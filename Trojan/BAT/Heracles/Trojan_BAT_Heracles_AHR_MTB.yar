
rule Trojan_BAT_Heracles_AHR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 27 06 07 9a 25 6f 90 01 01 00 00 0a 6f 90 01 01 01 00 0a 80 3a 00 00 04 28 90 01 01 00 00 06 28 90 01 01 01 00 0a 16 28 90 01 01 00 00 0a 07 17 58 0b 07 06 8e 69 32 d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHR_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 1f 64 20 d0 07 00 00 6f 19 00 00 0a 28 1a 00 00 0a 25 6f 1f 00 00 0a 72 90 01 01 00 00 70 6f 22 00 00 0a 25 6f 1f 00 00 0a 17 6f 23 00 00 0a 06 1f 64 20 d0 07 00 00 6f 19 00 00 0a 28 1a 00 00 0a 6f 24 00 00 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHR_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 58 1f 18 6a 58 11 09 6a 58 11 0a 1f 28 5a 6a 58 28 13 00 00 0a 13 0b 11 0b 28 17 00 00 0a 1f 2e 40 19 01 00 00 11 0b 28 12 00 00 0a 17 6a 58 28 } //01 00 
		$a_01_1 = {08 06 8e 69 28 0e 00 00 0a 1f 40 12 01 6f 12 00 00 06 26 06 16 08 06 8e 69 28 0f 00 00 0a 7e 04 00 00 04 08 06 8e 69 28 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHR_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.AHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 0b 72 90 01 01 00 00 70 0c 02 8e 69 17 33 06 02 16 9a 0c 2b 3a 02 8e 2d 2b 90 00 } //01 00 
		$a_01_1 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 69 00 73 00 20 00 65 00 6c 00 65 00 76 00 61 00 74 00 65 00 64 00 } //01 00  Process is elevated
		$a_01_2 = {41 00 74 00 74 00 65 00 6d 00 70 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 69 00 6e 00 6a 00 65 00 63 00 74 00 20 00 69 00 6e 00 74 00 6f 00 } //01 00  Attempting to inject into
		$a_01_3 = {53 68 65 6c 6c 63 6f 64 65 20 50 72 6f 63 65 73 73 20 49 6e 6a 65 63 74 6f 72 2e 70 64 62 } //00 00  Shellcode Process Injector.pdb
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHR_MTB_5{
	meta:
		description = "Trojan:BAT/Heracles.AHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 74 00 65 00 67 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 20 00 66 00 6f 00 72 00 20 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 42 00 79 00 74 00 65 00 73 00 20 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 } //01 00  Integration library for MalwareBytes antivirus service
		$a_01_1 = {4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 42 00 79 00 74 00 65 00 73 00 20 00 49 00 6e 00 74 00 65 00 67 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 6f 00 6c 00 75 00 74 00 69 00 6f 00 6e 00 73 00 } //01 00  MalwareBytes Integration Solutions
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {64 35 38 65 30 38 63 64 2d 33 62 39 62 2d 34 65 39 62 2d 62 30 34 61 2d 32 63 39 65 66 38 66 61 61 62 37 35 } //00 00  d58e08cd-3b9b-4e9b-b04a-2c9ef8faab75
	condition:
		any of ($a_*)
 
}