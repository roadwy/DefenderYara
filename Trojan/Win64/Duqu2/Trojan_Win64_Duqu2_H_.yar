
rule Trojan_Win64_Duqu2_H_{
	meta:
		description = "Trojan:Win64/Duqu2.H!!Duqu2.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 1e 8b 45 67 48 03 c7 48 3b d8 74 13 e8 a9 33 00 00 33 d2 41 b8 00 80 00 00 48 8b cb ff 50 58 } //01 00 
		$a_01_1 = {81 38 63 42 38 72 75 07 b8 01 00 00 00 eb 3d } //01 00 
		$a_01_2 = {c7 03 63 42 38 72 48 89 83 30 01 00 00 b8 01 00 00 00 eb 02 } //01 00 
		$a_01_3 = {41 c7 00 5c 00 42 00 41 c7 40 04 61 00 73 00 41 c7 40 08 65 00 4e 00 41 c7 40 0c 61 00 6d 00 41 c7 40 10 65 00 64 00 41 c7 40 14 4f 00 62 00 41 c7 40 18 6a 00 65 00 41 c7 40 1c 63 00 74 00 41 c7 40 20 73 00 5c 00 } //05 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Duqu2_H__2{
	meta:
		description = "Trojan:Win64/Duqu2.H!!Duqu2.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 09 48 83 c0 02 66 39 28 75 f7 c7 00 5c 00 4e 00 c7 40 04 54 00 44 00 b9 4c 00 4c 00 } //01 00 
		$a_01_1 = {66 c7 03 48 b8 4c 89 73 02 4c 8d 4c 24 40 44 8d 47 70 8b d7 48 8b ce 66 c7 43 0a ff e0 ff 55 28 } //01 00 
		$a_01_2 = {74 22 80 3e 4c 75 0b 48 8d 4e 03 80 39 b8 48 0f 44 f1 2b de c6 06 e9 b8 01 00 00 00 83 eb 05 89 5e 01 eb 02 } //01 00 
		$a_01_3 = {0f b7 01 b9 ab 4f 5e cd 33 c1 3d e6 15 5e cd 0f 85 8d 00 00 00 } //01 00 
		$a_01_4 = {43 8b 94 01 88 00 00 00 33 c1 49 03 d0 3d fb 0a 5e cd } //05 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Duqu2_H__3{
	meta:
		description = "Trojan:Win64/Duqu2.H!!Duqu2.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 14 81 7d 28 74 74 74 74 74 22 41 03 fe 81 ff 04 01 00 00 72 b9 } //01 00 
		$a_01_1 = {66 83 7b 02 6b 74 0c 48 83 c3 02 0f b7 03 66 85 c0 75 e7 66 83 3b 30 } //01 00 
		$a_01_2 = {0f b7 01 48 8b f9 b9 73 4f 00 63 33 c1 41 8b e9 3d 3e 15 00 63 } //01 00 
		$a_80_3 = {5c 5c 2e 5c 70 69 70 65 5c 7b 41 41 46 46 43 34 46 30 2d 45 30 34 42 2d 34 43 37 43 2d 42 34 30 41 2d 42 34 35 44 45 39 37 31 45 38 31 45 7d } //\\.\pipe\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}  01 00 
		$a_80_4 = {5c 5c 2e 5c 70 69 70 65 5c 7b 41 42 36 31 37 32 45 44 2d 38 31 30 35 2d 34 39 39 36 2d 39 44 32 41 2d 35 39 37 42 35 46 38 32 37 35 30 31 7d } //\\.\pipe\{AB6172ED-8105-4996-9D2A-597B5F827501}  05 00 
	condition:
		any of ($a_*)
 
}