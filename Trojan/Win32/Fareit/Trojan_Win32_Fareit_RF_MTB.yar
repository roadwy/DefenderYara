
rule Trojan_Win32_Fareit_RF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {49 f2 ed c5 30 4f 92 30 62 5d 13 e0 17 f2 8d dd 77 a5 } //01 00 
		$a_01_1 = {49 00 73 00 63 00 6f 00 62 00 61 00 71 00 75 00 65 00 62 00 75 00 2e 00 65 00 78 00 65 00 } //00 00  Iscobaquebu.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 52 50 a1 90 01 04 8b 40 90 01 01 99 03 04 24 13 54 24 90 01 01 83 c4 08 90 00 } //01 00 
		$a_03_1 = {8b 06 8b 00 25 ff ff 00 00 50 a1 90 01 04 50 e8 90 01 04 8b 16 89 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {40 2a 5c 41 50 72 6f 6a 65 63 74 31 } //01 00  @*\AProject1
		$a_81_1 = {31 38 35 2e 37 2e 32 31 34 2e 37 2f 41 44 53 31 31 2f 52 45 44 2e 50 4e 47 } //01 00  185.7.214.7/ADS11/RED.PNG
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 69 70 6c 6f 67 67 65 72 2e 6f 72 67 2f 31 70 75 63 75 37 } //00 00  https://iplogger.org/1pucu7
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {81 34 07 7c b1 6a 45 66 83 c0 00 f3 0f 7e ec 66 0f 6e d9 66 0f } //01 00 
		$a_01_1 = {46 6f 6c 6b 65 62 69 62 6c 69 6f 74 65 6b 65 72 6e 65 32 } //01 00  Folkebibliotekerne2
		$a_01_2 = {53 75 70 65 72 72 69 67 68 74 65 6f 75 73 6c 79 36 } //01 00  Superrighteously6
		$a_01_3 = {54 65 6b 6e 6f 6c 6f 67 69 76 75 72 64 65 72 69 6e 67 73 70 72 6f 6a 65 6b 74 65 74 39 } //00 00  Teknologivurderingsprojektet9
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Fareit.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_00_0 = {88 f5 81 34 37 1a 33 e5 b5 90 d9 eb eb 2e 6d 99 } //01 00 
		$a_81_1 = {49 65 62 47 6b 73 41 78 55 78 34 63 54 34 70 47 64 55 79 6f 4f 64 46 64 32 46 67 58 7a 5a 44 57 77 4d 46 55 46 32 32 39 } //01 00  IebGksAxUx4cT4pGdUyoOdFd2FgXzZDWwMFUF229
		$a_81_2 = {74 38 6d 75 6f 4e 6d 4c 32 45 46 75 36 59 77 50 45 4d 52 4a 71 67 63 73 63 70 49 6c 76 51 78 4f 45 32 31 38 36 } //00 00  t8muoNmL2EFu6YwPEMRJqgcscpIlvQxOE2186
	condition:
		any of ($a_*)
 
}