
rule Trojan_Win32_Ekstak_RP_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 53 56 57 e8 f2 ee f5 ff 89 45 fc e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RP_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 53 ff 15 b4 b4 64 00 8b d8 a1 24 fc 64 00 3b c7 75 7f 39 3d 28 fc 64 00 75 77 68 03 80 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RP_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {56 e8 1a 72 fb ff 8b f0 e9 } //01 00 
		$a_01_1 = {40 00 00 40 5f 74 61 62 6c 65 5f } //01 00 
		$a_01_2 = {40 00 00 40 2e 6d 70 65 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RP_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {d9 45 08 d8 c8 d9 05 38 84 56 00 d8 4d 08 d8 05 3c 84 56 00 de c9 d8 05 40 84 56 00 d8 0d 44 84 56 00 d9 5d fc 9b eb 3b d9 45 08 d8 1d 40 84 56 00 9b df e0 9e 73 27 d9 05 48 84 } //01 00 
		$a_01_1 = {74 2e 8a 06 46 8a 27 47 38 c4 74 f2 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 86 e0 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 38 e0 74 d2 1a c0 1c ff 0f be c0 eb 78 } //01 00 
		$a_01_2 = {65 00 53 00 49 00 4d 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //00 00  eSIM Client.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RP_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {0a c0 74 2e 8a 06 46 8a 27 47 38 c4 74 f2 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 86 e0 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 38 e0 74 d2 1a c0 1c ff 0f be c0 eb 78 } //01 00 
		$a_01_1 = {53 00 74 00 75 00 64 00 69 00 6f 00 4c 00 69 00 6e 00 65 00 50 00 68 00 6f 00 74 00 6f 00 2e 00 65 00 78 00 65 00 } //01 00  StudioLinePhoto.exe
		$a_01_2 = {70 00 72 00 6f 00 63 00 65 00 73 00 73 00 6c 00 61 00 73 00 73 00 6f 00 6c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  processlassolauncher.exe
		$a_01_3 = {71 00 75 00 69 00 63 00 6b 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  quickupgrade.exe
	condition:
		any of ($a_*)
 
}