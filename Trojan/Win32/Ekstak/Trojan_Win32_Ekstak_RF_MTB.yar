
rule Trojan_Win32_Ekstak_RF_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 53 56 57 b9 41 00 00 00 33 c0 bf 24 d4 4c 00 f3 ab } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 53 56 57 e8 75 ff ff ff 0f be d8 b9 41 00 00 00 33 c0 bf 54 f7 4c 00 f3 ab e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {a1 c8 2c 47 00 8b 4d 14 8b 15 a4 5e 48 00 50 51 52 6a 00 ff 15 90 01 01 f5 46 00 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c4 0c 8d 45 88 50 8d 85 88 fa ff ff ff d0 59 5f 5e 5b c9 c3 55 8b ec 56 e8 8c 63 e4 ff a3 70 6d 85 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 90 90 90 90 55 8b ec 56 8b 75 14 56 e8 39 a1 20 00 56 ff 15 68 60 65 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RF_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 8b 75 14 6a 00 6a 00 56 ff 15 90 01 01 e4 46 00 56 ff 15 90 01 01 e4 46 00 ff 15 90 01 01 e4 46 00 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RF_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 57 56 8b 7d 14 6a 03 e8 90 01 02 04 00 59 e9 90 01 03 00 90 00 } //01 00 
		$a_01_1 = {2e 69 6d 67 } //00 00  .img
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RF_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 32 e8 18 10 20 00 83 c4 04 8b 0d b4 fd 64 00 03 c8 89 0d b4 fd 64 00 e8 22 dd 16 00 8b c8 b8 90 01 04 33 d2 f7 f1 a3 98 fc 64 00 e8 3d 00 00 00 6a 00 6a 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RF_MTB_9{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 46 07 00 00 59 a3 a0 0b 08 01 e8 9b 07 00 00 8b c8 33 d2 b8 90 01 04 f7 f1 31 05 7c 0b 08 01 e8 90 01 01 0c 00 00 33 c0 50 50 e8 68 00 00 00 a3 80 0b 08 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RF_MTB_10{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c3 55 8b ec 83 ec 03 83 e4 f8 83 c4 04 56 56 6a 03 e8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RF_MTB_11{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 01 05 55 8b ec 56 8b 75 14 56 e8 90 01 01 9f 20 00 ff 15 90 01 02 65 00 e9 90 00 } //01 00 
		$a_01_1 = {53 00 6d 00 61 00 72 00 74 00 20 00 54 00 75 00 72 00 6e 00 20 00 4f 00 66 00 66 00 20 00 43 00 4f 00 4d 00 70 00 75 00 74 00 65 00 72 00 } //00 00  Smart Turn Off COMputer
	condition:
		any of ($a_*)
 
}