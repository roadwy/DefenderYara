
rule Trojan_BAT_Remcos_ARM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 38 16 0b 2b 21 08 06 07 28 90 01 03 06 13 09 09 12 09 28 90 01 03 0a 8c 07 00 00 01 28 90 01 03 06 26 07 17 58 0b 07 08 28 90 01 03 06 fe 04 13 06 11 06 2d d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARM_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 05 16 11 06 6f 81 00 00 0a 00 00 08 11 05 16 11 05 8e 69 6f 82 00 00 0a 25 13 06 16 fe 02 } //01 00 
		$a_03_1 = {7b 28 00 00 04 59 0c 90 01 09 06 5a 06 5a 07 07 5a 58 08 08 5a 58 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARM_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 15 02 07 03 28 12 00 00 06 2c 07 06 07 6f 35 00 00 0a 07 17 58 0b 07 02 8e 69 32 e5 } //01 00 
		$a_01_1 = {0a 16 0b 2b 13 06 07 02 28 1f 00 00 06 07 6f 6c 00 00 0a a2 07 17 58 0b 07 02 28 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARM_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 9a 0c 08 19 8d 47 00 00 01 25 16 7e 2e 00 00 04 16 9a a2 25 17 7e 2e 00 00 04 17 9a a2 25 18 } //02 00 
		$a_03_1 = {16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc 90 00 } //01 00 
		$a_01_2 = {54 6f 75 72 6e 61 6d 65 6e 74 4c 69 62 72 61 72 79 } //00 00  TournamentLibrary
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARM_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 02 8e 69 20 00 10 00 00 1f 40 28 90 01 01 00 00 06 0a 16 0b 25 06 02 02 8e 69 12 01 28 90 01 01 00 00 06 26 7e 90 01 01 00 00 0a 0c 7e 90 01 01 00 00 0a 16 20 ff 0f 00 00 28 90 01 01 00 00 0a 7e 90 01 01 00 00 0a 1a 12 02 28 90 00 } //01 00 
		$a_01_1 = {0a 16 0b 2b 22 06 07 9a 0c 08 6f 2f 00 00 0a 6f 30 00 00 0a 02 28 14 00 00 0a 2c 07 08 6f 31 00 00 0a 2a 07 17 58 0b 07 06 8e 69 32 d8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_ARM_MTB_6{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 41 63 63 6f 75 6e 74 43 6f 6e 74 72 6f 6c } //01 00  RestaurantApp.AccountControl
		$a_01_1 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 43 6f 6e 74 61 63 74 43 6f 6e 74 72 6f 6c } //01 00  RestaurantApp.ContactControl
		$a_01_2 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 44 65 66 61 75 6c 74 43 6f 6e 74 72 6f 6c } //01 00  RestaurantApp.DefaultControl
		$a_01_3 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 4c 6f 67 69 6e 43 6f 6e 74 72 6f 6c } //01 00  RestaurantApp.LoginControl
		$a_01_4 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 4d 65 6e 75 43 6f 6e 74 72 6f 6c } //01 00  RestaurantApp.MenuControl
		$a_01_5 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 4e 75 74 72 69 74 69 6f 6e 43 6f 6e 74 72 6f 6c } //01 00  RestaurantApp.NutritionControl
		$a_01_6 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 52 65 73 74 61 75 72 61 6e 74 43 6f 6e 74 72 6f 6c } //01 00  RestaurantApp.RestaurantControl
		$a_01_7 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 57 65 6c 63 6f 6d 65 43 6f 6e 74 72 6f 6c } //01 00  RestaurantApp.WelcomeControl
		$a_01_8 = {65 30 34 63 63 62 37 65 2d 64 38 32 64 2d 34 33 63 37 2d 39 39 34 36 2d 31 33 38 34 36 39 65 66 38 33 30 63 } //00 00  e04ccb7e-d82d-43c7-9946-138469ef830c
	condition:
		any of ($a_*)
 
}