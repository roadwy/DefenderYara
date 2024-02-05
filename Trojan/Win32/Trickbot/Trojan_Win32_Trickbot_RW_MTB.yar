
rule Trojan_Win32_Trickbot_RW_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 4d 90 01 01 8b 09 8a 0c 39 02 0d 90 01 04 30 08 8b 0d 90 01 04 0f af 0d 90 01 04 8b 35 90 01 04 ff 45 90 01 01 8b c6 2b c1 6b c0 70 03 45 90 01 01 39 45 90 01 01 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5e 32 3f 53 6e 72 77 6b 5a 53 7a 70 75 50 49 } //0a 00 
		$a_01_1 = {46 75 63 6b 20 44 65 66 } //01 00 
		$a_01_2 = {47 65 74 4b 65 79 53 74 61 74 65 } //01 00 
		$a_01_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00 
		$a_01_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00 
		$a_01_5 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f 41 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 44 24 90 01 01 88 1c 2e 8b 3d 90 01 04 40 41 3b c7 89 44 24 18 72 90 00 } //01 00 
		$a_81_1 = {23 61 29 46 26 53 50 66 63 45 67 72 47 74 46 63 34 74 72 6a 79 35 4a 73 35 37 21 77 4d 41 6c 73 4c 3f 30 64 6c 4a 41 47 35 3e 62 53 47 72 62 4b 37 40 75 33 73 61 58 6c 6c 74 65 51 31 5e 2a 71 6a 57 2a 35 48 7a 26 44 56 50 50 69 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_RW_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 35 90 01 04 a1 90 01 04 8d 04 80 2b d0 03 d5 8b 2d 90 01 04 03 d5 8b 6c 24 90 01 01 8a 14 0a 8a 45 90 01 01 32 c2 43 88 45 90 01 01 8b 44 24 90 01 01 3b d8 0f 90 00 } //01 00 
		$a_01_1 = {31 50 2b 33 46 4e 3f 66 65 28 45 41 69 42 62 49 56 25 71 54 6a 25 41 6a 5f 4c 63 42 26 73 32 70 4b 39 79 59 68 23 72 49 48 3c 6d 49 4d 26 62 58 2a 6d 21 5e 28 70 26 75 6c 5e 51 23 2a 39 3e 78 42 67 61 6d 29 33 64 59 79 48 6f 5e 44 75 24 46 3e 7a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_RW_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 05 00 "
		
	strings :
		$a_02_0 = {c1 e9 02 8d b8 90 01 04 b8 01 01 01 01 f3 ab 8b ca 83 e1 03 f3 aa 8b 4c 24 90 01 01 8b 54 24 90 01 01 8d 44 24 90 01 01 50 53 51 6a 90 01 01 68 90 01 04 52 89 5c 24 90 01 01 ff 54 24 90 01 01 85 c0 75 90 01 01 5f 5e 5d 32 c0 90 00 } //01 00 
		$a_01_1 = {5f 7a 31 4c 42 75 64 58 56 63 7a 3c 67 54 62 } //01 00 
		$a_01_2 = {73 35 56 4d 3f 39 44 40 52 71 21 21 73 55 5a } //01 00 
		$a_01_3 = {6d 73 75 79 44 43 59 6a 46 26 49 51 34 45 59 } //01 00 
		$a_01_4 = {42 72 78 75 5f 6c 61 44 26 51 68 65 39 53 6f } //01 00 
		$a_01_5 = {72 44 6c 3c 4f 6c 76 4e 72 78 77 30 6e 35 32 } //01 00 
		$a_01_6 = {34 6c 32 61 25 38 58 7a 65 4f 62 38 56 47 28 } //00 00 
	condition:
		any of ($a_*)
 
}