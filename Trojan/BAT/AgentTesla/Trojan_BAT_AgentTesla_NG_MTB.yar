
rule Trojan_BAT_AgentTesla_NG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 08 91 11 90 01 01 61 13 0b 07 11 90 01 01 07 8e 69 5d 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {25 26 0c 1f 61 6a 08 28 90 01 03 2b 25 26 80 90 01 03 04 09 20 90 01 03 25 5a 20 90 01 03 4b 61 2b 84 06 28 90 01 03 0a 0b 09 20 90 01 03 4a 5a 20 84 90 01 03 61 38 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NG_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 ce 21 00 70 06 28 90 01 03 0a 08 20 90 01 03 2d 5a 20 90 01 03 ef 61 38 90 01 03 ff 06 72 90 01 03 70 28 90 01 03 0a 0a 08 20 90 01 03 c5 5a 20 90 01 03 3e 61 38 90 01 03 ff 06 72 90 01 03 70 28 90 01 03 0a 0a 08 20 90 01 03 c6 5a 20 90 01 03 27 61 38 90 01 03 ff 73 90 01 03 0a 25 6f 90 01 03 0a 17 6f 90 01 03 0a 25 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {41 73 74 72 6f 46 4e 4c 61 75 6e 63 68 65 72 } //01 00  AstroFNLauncher
		$a_01_2 = {64 00 65 00 6c 00 20 00 54 00 72 00 69 00 6e 00 69 00 74 00 79 00 2e 00 62 00 61 00 74 00 } //00 00  del Trinity.bat
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NG_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 54 79 70 65 43 6f 6d 70 } //01 00  ITypeComp
		$a_81_1 = {41 74 68 6c 65 74 69 63 43 6c 75 62 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 53 70 6c 61 73 68 53 63 72 65 65 6e 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  AthleticClubManagementSystem.SplashScreen1.resources
		$a_81_2 = {41 74 68 6c 65 74 69 63 43 6c 75 62 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //01 00  AthleticClubManagementSystem.Resources
		$a_81_3 = {50 6f 6f 6c 41 77 61 69 74 61 62 6c 65 } //01 00  PoolAwaitable
		$a_81_4 = {74 78 74 41 6d 6f 75 6e 74 50 61 69 64 } //01 00  txtAmountPaid
		$a_81_5 = {41 74 68 6c 65 74 69 63 43 6c 75 62 44 42 } //01 00  AthleticClubDB
		$a_81_6 = {24 32 34 38 62 35 63 35 39 2d 61 32 66 38 2d 34 38 64 35 2d 38 36 37 32 2d 34 38 63 64 61 39 31 30 38 34 35 38 } //00 00  $248b5c59-a2f8-48d5-8672-48cda9108458
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NG_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 54 38 55 00 00 00 38 90 01 03 00 38 90 01 03 00 38 90 01 03 00 16 2c 03 90 00 } //01 00 
		$a_01_1 = {2f 00 2f 00 65 00 6e 00 64 00 69 00 72 00 65 00 63 00 74 00 32 00 2e 00 66 00 72 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 77 00 69 00 74 00 68 00 6f 00 75 00 74 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 5f 00 45 00 67 00 61 00 65 00 6f 00 69 00 74 00 68 00 2e 00 6a 00 70 00 67 00 } //01 00  //endirect2.fr/loader/uploads/withoutstartup_Egaeoith.jpg
		$a_01_2 = {4c 00 68 00 71 00 7a 00 61 00 6d 00 6f 00 73 00 73 00 76 00 6e 00 } //01 00  Lhqzamossvn
		$a_01_3 = {4d 00 61 00 6b 00 65 00 20 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 66 00 61 00 73 00 74 00 65 00 72 00 20 00 61 00 6e 00 64 00 20 00 6d 00 6f 00 72 00 65 00 20 00 73 00 65 00 63 00 75 00 72 00 65 00 } //01 00  Make Computer faster and more secure
		$a_01_4 = {4b 00 44 00 45 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 73 00 } //01 00  KDE Softwares
		$a_01_5 = {43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 53 00 65 00 6e 00 74 00 69 00 6e 00 65 00 6c 00 } //00 00  Computer Sentinel
	condition:
		any of ($a_*)
 
}