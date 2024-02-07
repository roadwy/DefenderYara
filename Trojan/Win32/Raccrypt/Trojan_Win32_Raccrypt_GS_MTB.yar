
rule Trojan_Win32_Raccrypt_GS_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 0c 32 83 3d 90 01 04 33 90 00 } //01 00 
		$a_02_1 = {30 04 31 81 bc 24 90 01 04 91 05 00 00 90 18 46 3b b4 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6c 89 1a 60 c7 44 24 90 01 01 b8 38 69 0e c7 44 24 90 01 01 7d 00 8d 51 c7 44 24 90 01 01 d2 fb 1a 43 c7 44 24 90 01 01 2c 31 1b 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {36 23 01 00 8b 0d 90 02 04 88 04 0f 81 3d 90 02 04 66 0c 00 00 90 00 } //01 00 
		$a_00_1 = {8b 44 24 04 8b 4c 24 08 31 08 c2 08 00 } //01 00 
		$a_00_2 = {8b 44 24 08 8b 4c 24 04 c1 e0 04 89 01 c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 0a 72 00 c6 05 90 01 04 61 c6 05 90 01 04 65 c6 05 90 01 04 75 c6 05 90 01 04 6c c6 05 90 01 04 69 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 72 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c7 45 f8 40 00 00 00 c6 05 90 01 04 65 c6 05 90 01 04 50 c6 05 90 01 04 00 c6 05 90 01 04 7c c6 05 90 01 04 63 c6 05 90 01 04 61 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 75 90 00 } //01 00 
		$a_00_1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //00 00  kernel32.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {55 8b ec 81 ec 90 01 04 c6 05 90 01 04 6c c6 05 90 01 04 69 c6 05 90 01 04 88 c6 05 90 01 04 79 c6 05 90 01 04 92 c6 05 90 01 04 6a 68 90 01 04 ff 15 90 01 04 a3 90 01 04 c7 85 90 00 } //02 00 
		$a_02_1 = {b8 36 23 01 00 01 45 fc 8b 90 02 05 03 90 01 01 08 8b 90 01 01 fc 03 90 01 01 08 8a 90 01 01 88 90 01 01 8b 90 01 01 5d c2 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GS_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 45 08 8b 45 08 c9 c2 08 00 81 00 eb 34 ef c6 c3 } //00 00 
	condition:
		any of ($a_*)
 
}