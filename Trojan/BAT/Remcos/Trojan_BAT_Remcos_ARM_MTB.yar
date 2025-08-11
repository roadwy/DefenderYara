
rule Trojan_BAT_Remcos_ARM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 16 13 22 2b 2f 11 07 11 06 8e 69 5d 13 23 11 06 11 23 11 21 11 22 91 9c 03 11 21 11 22 91 6f ?? 00 00 0a 11 07 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARM_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 38 16 0b 2b 21 08 06 07 28 ?? ?? ?? 06 13 09 09 12 09 28 ?? ?? ?? 0a 8c 07 00 00 01 28 ?? ?? ?? 06 26 07 17 58 0b 07 08 28 ?? ?? ?? 06 fe 04 13 06 11 06 2d d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARM_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0c 2b 21 00 11 07 11 0c 11 06 08 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 9d 00 11 0c 17 58 13 0c 11 0c 11 07 8e 69 fe 04 13 0d 11 0d 2d d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARM_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 16 11 06 6f 81 00 00 0a 00 00 08 11 05 16 11 05 8e 69 6f 82 00 00 0a 25 13 06 16 fe 02 } //1
		$a_03_1 = {7b 28 00 00 04 59 0c ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 5a 06 5a 07 07 5a 58 08 08 5a 58 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Remcos_ARM_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 30 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 6f ?? 00 00 0a 04 32 01 2a 07 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARM_MTB_6{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 15 02 07 03 28 12 00 00 06 2c 07 06 07 6f 35 00 00 0a 07 17 58 0b 07 02 8e 69 32 e5 } //1
		$a_01_1 = {0a 16 0b 2b 13 06 07 02 28 1f 00 00 06 07 6f 6c 00 00 0a a2 07 17 58 0b 07 02 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Remcos_ARM_MTB_7{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 16 0d 16 0d 2b 6a 06 09 06 8e 69 5d 1f 37 59 1f 37 58 06 09 06 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 19 58 19 59 91 08 09 08 8e 69 5d 1f 09 58 1f 0a 58 1f 13 59 1c 58 1c 59 91 61 06 09 20 11 02 00 00 58 20 10 02 00 00 59 06 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 1c 58 1c 59 91 59 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARM_MTB_8{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 17 2b 63 00 11 06 17 58 20 ff 00 00 00 5f 13 06 11 05 11 04 11 06 95 58 20 ff 00 00 00 5f 13 05 02 11 04 11 06 8f 7d 00 00 01 11 04 11 05 8f 7d 00 00 01 28 ?? 00 00 06 00 11 04 11 06 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 18 09 11 17 07 11 17 91 11 04 11 18 95 61 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARM_MTB_9{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 3a 16 0b 2b 13 02 06 07 03 04 28 ?? 00 00 06 28 ?? 00 00 06 07 17 58 0b 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0c 08 2d d4 } //2
		$a_03_1 = {02 03 04 6f ?? 00 00 0a 0a 0e 04 05 6f ?? 00 00 0a 59 0b 06 07 05 28 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Remcos_ARM_MTB_10{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 12 29 28 ?? 00 00 0a 58 13 0a 11 0b 12 29 28 ?? 00 00 0a 58 13 0b 11 0c 12 29 28 ?? 00 00 0a 58 13 0c 12 29 28 ?? 00 00 0a 12 29 28 ?? 00 00 0a 58 12 29 28 ?? 00 00 0a 58 13 2a 11 2a 11 0d 31 04 11 2a 13 0d 11 2a 11 0e 2f 04 11 2a 13 0e 11 27 11 07 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARM_MTB_11{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 9a 0c 08 19 8d 47 00 00 01 25 16 7e 2e 00 00 04 16 9a a2 25 17 7e 2e 00 00 04 17 9a a2 25 18 } //2
		$a_03_1 = {16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc } //2
		$a_01_2 = {54 6f 75 72 6e 61 6d 65 6e 74 4c 69 62 72 61 72 79 } //1 TournamentLibrary
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_Remcos_ARM_MTB_12{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0b 2b 5f 00 11 05 17 58 20 ff 00 00 00 5f 13 05 11 06 11 04 11 05 95 58 20 ff 00 00 00 5f 13 06 02 11 04 11 05 8f ?? 00 00 01 11 04 11 06 8f ?? 00 00 01 28 ?? 00 00 06 00 11 04 11 05 95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 0c 02 11 0b 07 09 11 04 11 0c 28 ?? 00 00 06 00 00 11 0b 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARM_MTB_13{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 12 2b 63 00 11 07 17 58 20 ff 00 00 00 5f 13 07 11 05 11 04 11 07 95 58 20 ff 00 00 00 5f 13 05 11 04 11 07 95 13 06 11 04 11 07 11 04 11 05 95 9e 11 04 11 05 11 06 9e 11 04 11 07 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 13 11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 9c 00 11 12 17 58 13 12 11 12 09 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARM_MTB_14{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 8e 69 20 00 10 00 00 1f 40 28 ?? 00 00 06 0a 16 0b 25 06 02 02 8e 69 12 01 28 ?? 00 00 06 26 7e ?? 00 00 0a 0c 7e ?? 00 00 0a 16 20 ff 0f 00 00 28 ?? 00 00 0a 7e ?? 00 00 0a 1a 12 02 28 } //1
		$a_01_1 = {0a 16 0b 2b 22 06 07 9a 0c 08 6f 2f 00 00 0a 6f 30 00 00 0a 02 28 14 00 00 0a 2c 07 08 6f 31 00 00 0a 2a 07 17 58 0b 07 06 8e 69 32 d8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Remcos_ARM_MTB_15{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 00 09 07 08 6f ?? 00 00 0a 00 00 de 0b 09 2c 07 09 6f ?? 00 00 0a 00 dc 08 28 } //1
		$a_03_1 = {0a 00 25 17 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 0a 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 de 23 0b 00 72 ?? 01 00 70 07 6f } //2
		$a_03_2 = {0a 00 25 17 6f ?? 00 00 0a 00 25 72 ?? 01 00 70 6f ?? 00 00 0a 00 0a 00 06 28 ?? 00 00 0a 26 00 de 05 26 00 00 de 00 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*3) >=6
 
}
rule Trojan_BAT_Remcos_ARM_MTB_16{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 41 63 63 6f 75 6e 74 43 6f 6e 74 72 6f 6c } //1 RestaurantApp.AccountControl
		$a_01_1 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 43 6f 6e 74 61 63 74 43 6f 6e 74 72 6f 6c } //1 RestaurantApp.ContactControl
		$a_01_2 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 44 65 66 61 75 6c 74 43 6f 6e 74 72 6f 6c } //1 RestaurantApp.DefaultControl
		$a_01_3 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 4c 6f 67 69 6e 43 6f 6e 74 72 6f 6c } //1 RestaurantApp.LoginControl
		$a_01_4 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 4d 65 6e 75 43 6f 6e 74 72 6f 6c } //1 RestaurantApp.MenuControl
		$a_01_5 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 4e 75 74 72 69 74 69 6f 6e 43 6f 6e 74 72 6f 6c } //1 RestaurantApp.NutritionControl
		$a_01_6 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 52 65 73 74 61 75 72 61 6e 74 43 6f 6e 74 72 6f 6c } //1 RestaurantApp.RestaurantControl
		$a_01_7 = {52 65 73 74 61 75 72 61 6e 74 41 70 70 2e 57 65 6c 63 6f 6d 65 43 6f 6e 74 72 6f 6c } //1 RestaurantApp.WelcomeControl
		$a_01_8 = {65 30 34 63 63 62 37 65 2d 64 38 32 64 2d 34 33 63 37 2d 39 39 34 36 2d 31 33 38 34 36 39 65 66 38 33 30 63 } //1 e04ccb7e-d82d-43c7-9946-138469ef830c
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule Trojan_BAT_Remcos_ARM_MTB_17{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 6f 6c 61 72 61 42 6f 6f 74 73 74 72 61 70 70 65 72 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 42 6f 6f 74 73 74 72 61 70 70 65 72 2e 70 64 62 } //2 SolaraBootstrapper\bin\Release\Bootstrapper.pdb
		$a_01_1 = {4e 00 65 00 77 00 20 00 62 00 6f 00 6f 00 74 00 73 00 74 00 72 00 61 00 70 00 70 00 65 00 72 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 } //2 New bootstrapper downloaded
		$a_01_2 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 20 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 } //1 /silent /install
		$a_01_3 = {57 00 65 00 62 00 56 00 69 00 65 00 77 00 32 00 20 00 72 00 75 00 6e 00 74 00 69 00 6d 00 65 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 } //1 WebView2 runtime installed successfully
		$a_01_4 = {2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 20 00 2f 00 6e 00 6f 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 } //1 /install /quiet /norestart
		$a_01_5 = {6b 00 69 00 6c 00 6c 00 69 00 6e 00 67 00 20 00 53 00 6f 00 6c 00 61 00 72 00 61 00 2e 00 65 00 78 00 65 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 killing Solara.exe process
		$a_01_6 = {6b 00 69 00 6c 00 6c 00 69 00 6e 00 67 00 20 00 6e 00 6f 00 64 00 65 00 2e 00 65 00 78 00 65 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 killing node.exe process
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}