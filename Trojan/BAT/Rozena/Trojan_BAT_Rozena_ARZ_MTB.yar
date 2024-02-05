
rule Trojan_BAT_Rozena_ARZ_MTB{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 0a 28 01 00 00 0a 16 9a 28 02 00 00 0a 06 28 03 00 00 0a 39 00 00 00 00 2a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_2{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 13 16 2b 15 07 11 16 07 11 16 91 20 fa 00 00 00 61 d2 9c 11 16 17 58 13 16 11 16 07 8e 69 32 e4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_3{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0b 16 13 06 2b 18 07 11 06 07 11 06 91 1f 22 61 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_4{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 06 16 08 07 28 90 01 03 0a 7e 02 00 00 0a 16 08 7e 02 00 00 0a 16 7e 02 00 00 0a 28 90 01 03 06 0d 09 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_5{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 07 16 08 6e 28 90 01 03 0a 07 8e 69 28 90 01 03 0a 00 7e 0c 00 00 0a 0d 16 13 04 7e 0c 00 00 0a 13 05 16 16 08 11 05 16 12 04 28 90 01 03 06 0d 09 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_6{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 8d 15 00 00 01 0b 16 0c 2b 0f 07 08 06 08 93 28 90 01 03 0a 9c 08 17 58 0c 08 07 8e 69 32 eb 90 00 } //01 00 
		$a_01_1 = {6e 00 69 00 65 00 74 00 76 00 35 00 36 00 37 00 } //01 00 
		$a_01_2 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4c 00 6f 00 79 00 65 00 69 00 6e 00 44 00 42 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 41 00 50 00 49 00 } //00 00 
	condition:
		any of ($a_*)
 
}