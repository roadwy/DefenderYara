
rule Trojan_Win32_Zenpak_RG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 18 83 c0 09 29 c2 8d 05 90 01 04 89 28 83 f2 05 83 e8 07 83 f2 09 31 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 ab aa aa aa 89 44 24 90 01 01 f7 e1 c1 ea 03 6b c2 0c 8b 4c 24 90 01 01 29 c1 89 c8 83 e8 04 89 4c 24 90 01 01 89 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RG_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 cd cc cc cc 89 44 24 90 01 01 f7 e1 c1 ea 04 6b c2 14 8b 4c 24 90 01 01 29 c1 89 c8 83 e8 07 89 4c 24 90 01 01 89 44 24 90 01 01 74 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RG_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe ff ff 89 c1 88 ca 83 e8 4d 88 95 90 01 01 fe ff ff 89 85 90 01 01 fe ff ff 74 90 01 01 eb 00 8a 85 90 01 01 fe ff ff 0f b6 c8 83 e9 54 89 8d 90 01 01 fe ff ff 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RG_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 3c 0e 88 1c 16 0f b6 0c 0e 01 f9 81 e1 90 01 04 8a 1c 0e 8b 4d 90 01 01 8b 7d 90 01 01 32 1c 39 8b 4d 90 01 01 88 1c 39 8b 4d 90 01 01 01 cf 8b 4d 90 01 01 39 cf 8b 4d 90 01 01 89 4d 90 01 01 89 55 90 01 01 89 7d 90 01 01 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RG_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {fe ff ff 45 75 1e 80 bd 90 01 01 fe ff ff 4c 75 15 31 c0 80 bd 90 01 01 fe ff ff 2e 89 85 90 01 01 fe ff ff 0f 84 90 01 01 ff ff ff 90 00 } //01 00 
		$a_01_1 = {41 72 66 72 75 69 74 66 75 6c 73 61 77 2e 6c 69 6b 65 6e 65 73 73 63 69 73 6e 2e 74 2e 6b 64 6f 6e 2e 74 67 72 65 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_RG_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {89 84 24 98 00 00 00 89 e0 8d 8c 24 98 00 00 00 89 48 0c c7 40 08 93 0a 00 00 c7 40 04 f0 07 00 00 c7 00 ba 9b 38 00 a1 10 b0 01 10 ff d0 83 ec 10 89 e1 8d 94 24 90 00 00 00 89 51 04 c7 01 05 c8 a3 00 8b 0d 38 b0 01 10 } //01 00 
		$a_01_1 = {74 68 65 6d 74 68 65 69 72 46 33 4e 73 75 62 64 75 65 77 68 6f 73 65 31 66 72 75 69 74 66 75 6c 74 68 65 69 72 } //01 00 
		$a_01_2 = {79 65 61 72 73 36 74 6f 67 65 74 68 65 72 75 73 79 69 65 6c 64 69 6e 67 54 72 65 65 6c 67 61 74 68 65 72 65 64 } //01 00 
		$a_01_3 = {6b 69 6e 64 2e 74 68 69 72 64 6c 69 67 68 74 2e 4f 61 6e 64 73 65 61 73 6f 6e 73 41 69 72 63 61 6e 2e 74 2c 36 64 6f 6d 69 6e 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}