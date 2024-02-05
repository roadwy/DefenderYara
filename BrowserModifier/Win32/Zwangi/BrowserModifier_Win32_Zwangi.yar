
rule BrowserModifier_Win32_Zwangi{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 26 74 0a 3c 3d 74 06 } //01 00 
		$a_01_1 = {8b 55 ec 3b 55 f4 74 6a 8b 45 fc 83 c0 01 25 ff 00 00 00 89 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_2{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 80 3e 20 74 fa 80 3e 22 75 08 b9 22 00 00 00 46 eb 05 b9 20 00 00 00 8b de } //01 00 
		$a_01_1 = {5a 75 6d 69 65 20 6c 6f 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_3{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {80 3e 2d 75 64 8a 46 01 3c 78 75 5d 80 7e 02 72 75 2c } //01 00 
		$a_01_1 = {2d 52 00 00 2d 72 00 } //01 00 
		$a_01_2 = {5d 3e 5d 3e 5d 3e 5d 3e } //01 00 
		$a_01_3 = {3c 5b 3c 5b 3c 5b 3c 5b } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_4{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 1c c6 85 90 01 02 ff ff 22 8b 4d fc 83 c1 01 8b 95 90 01 02 ff ff 89 8c 95 90 00 } //01 00 
		$a_03_1 = {eb 12 8b 8d 90 01 02 ff ff 8b 55 fc 89 94 8d 90 01 02 ff ff eb 09 c6 85 90 01 02 ff ff 20 eb 90 00 } //01 00 
		$a_01_2 = {83 c4 04 f7 d8 eb 1a 0f b6 4d 0c 85 c9 74 0e 8b 4d 08 51 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_5{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d 3e 5d 3e 5d 3e 5d 3e 00 00 00 00 3c 5b 3c 5b 3c 5b 3c 5b } //01 00 
		$a_01_1 = {83 7d f0 00 76 0c 8b 45 ec 8b 4d 08 8b 11 89 10 eb dc b8 01 00 00 00 c1 e0 02 } //01 00 
		$a_03_2 = {ff 6a 08 8b 0d 98 90 01 01 40 00 51 8b 55 fc 52 8b 85 90 01 01 ec ff ff 50 e8 90 01 02 00 00 83 c4 10 89 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_6{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 cc 0f be 48 01 83 f9 78 0f 85 90 01 04 c7 85 90 01 08 c7 85 90 01 08 8b 95 90 01 04 8b 85 90 01 04 8d 8c 10 90 01 04 89 8d 90 01 04 8b 55 cc 83 c2 02 52 e8 90 00 } //01 00 
		$a_01_1 = {83 7d f0 00 76 0c 8b 45 ec 8b 4d 08 8b 11 89 10 eb dc b8 01 00 00 00 c1 e0 02 } //01 00 
		$a_01_2 = {2d 72 00 00 2d 52 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_7{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c3 83 f8 05 75 06 b8 80 00 00 00 c3 3d } //01 00 
		$a_01_1 = {8d 04 82 8b 04 08 5f 03 c1 5d d1 e0 5b d1 e8 5e } //01 00 
		$a_03_2 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 90 01 04 5f 5e 5b c9 c3 90 00 } //01 00 
		$a_03_3 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f 90 02 20 01 00 00 00 09 00 00 00 09 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_8{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 81 80 13 00 00 8b 54 81 fc 8b fa c1 ef 1e 33 fa 69 ff 65 89 07 6c 03 f8 89 3c 81 8b 91 80 13 00 00 42 8b c2 3d 70 02 00 00 89 91 80 13 00 00 7c ce } //01 00 
		$a_01_1 = {8b 55 ec 3b 55 f4 74 6a 8b 45 fc 83 c0 01 25 ff 00 00 00 89 45 fc } //01 00 
		$a_00_2 = {3c 26 74 04 3c 3d 75 02 b0 5f } //01 00 
		$a_00_3 = {3c 3d 74 04 3c 26 75 02 b0 5f } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_9{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 d8 1b c0 83 e0 70 83 c0 10 eb 90 01 01 f7 c1 00 00 00 40 90 00 } //01 00 
		$a_03_1 = {8a 14 01 88 10 48 3d 90 01 04 73 90 01 01 68 90 01 04 c7 05 90 01 08 ff d6 90 00 } //01 00 
		$a_01_2 = {74 31 0f be c0 83 e8 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02 } //01 00 
		$a_03_3 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 90 01 04 5f 5e 5b c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_10{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f be c0 83 e8 61 b3 1a f6 eb 02 c2 2c 61 41 } //01 00 
		$a_03_1 = {8a 44 24 08 8b 4c 24 04 f6 d8 55 56 57 1b c0 25 90 01 04 05 90 01 04 8d 6c 08 ff 3b cd 90 00 } //01 00 
		$a_03_2 = {b0 01 5b 59 c3 8b cd e8 90 01 04 5f 5e c6 45 90 01 01 01 5d 32 c0 90 00 } //01 00 
		$a_03_3 = {8b c1 99 f7 7c 24 50 33 c0 8a 04 2a 33 d2 8a 91 90 01 04 03 d6 03 c2 25 ff 00 00 00 8b f0 3b ce 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_11{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 04 84 c0 75 06 b8 01 00 00 00 c3 6a 00 ff 15 90 01 04 68 90 01 04 e8 90 01 04 83 c4 04 85 c0 75 06 b8 02 00 00 00 c3 ff e0 90 00 } //01 00 
		$a_03_1 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 90 01 04 5f 5e 5b c9 c3 90 00 } //01 00 
		$a_03_2 = {2b f0 8a 50 ff 48 3b c1 88 14 06 90 01 01 f5 90 00 } //01 00 
		$a_01_3 = {8d 04 82 8b 04 08 5f 03 c1 5d d1 e0 5b d1 e8 5e } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_12{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d cc 0f be 11 83 fa 2d 0f 85 90 01 02 00 00 8b 45 cc 0f be 48 01 83 f9 78 0f 85 90 01 02 00 00 8b 55 cc 0f be 42 02 83 f8 72 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_03_1 = {83 fa 2d 0f 85 90 01 31 90 03 03 00 90 01 2d 8b 45 90 01 01 0f be 48 01 83 f9 78 0f 85 90 01 31 90 03 03 00 90 01 2d 8b 55 90 01 01 0f be 42 02 83 f8 72 0f 85 90 00 } //01 00 
		$a_01_2 = {2d 72 00 00 2d 52 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_13{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 ec 74 01 00 00 e9 90 01 04 8b 55 10 89 15 a4 72 40 00 eb 90 01 01 83 7d ec 00 75 90 01 01 8b 4d e8 51 ff 55 f8 e9 90 00 } //01 00 
		$a_03_1 = {c7 05 a0 72 40 00 00 00 00 00 90 03 01 01 eb e9 90 00 } //01 00 
		$a_03_2 = {0f be 02 83 f8 22 75 5a eb 90 01 01 eb 90 00 } //01 00 
		$a_03_3 = {f7 d9 ff 24 8d 90 01 02 40 00 8d 49 00 8b c7 ba 03 00 00 00 83 f9 04 72 90 01 01 83 e0 03 2b c8 ff 24 85 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_14{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {a4 00 00 00 05 a0 00 00 00 85 d2 76 90 01 01 8b 51 04 57 8b 38 8b 04 3a 03 d7 85 c0 76 90 01 01 53 55 56 8b 71 04 03 f0 8b 42 04 83 e8 08 33 db a9 fe ff ff ff 8d 7a 08 76 90 01 01 8d 9b 00 00 00 00 33 c0 66 8b 07 8b e8 81 e5 00 f0 00 00 81 fd 00 30 00 00 90 00 } //01 00 
		$a_03_1 = {8b 74 24 20 66 81 3e 4d 5a c6 44 24 18 01 74 0c 68 90 01 02 00 10 8b cf e8 90 01 04 53 8b 5e 3c 8b 04 33 03 de 3d 50 45 00 00 74 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_15{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {04 e0 80 f9 61 7c 08 80 f9 7a 7f 03 80 c1 e0 3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7 33 d2 3a c1 0f 94 c2 8a c2 5e c3 } //01 00 
		$a_00_1 = {01 28 8b 42 04 83 e8 08 43 d1 e8 83 c7 02 3b d8 72 } //01 00 
		$a_01_2 = {99 f7 fd 33 c0 8a 04 1a 33 d2 8a 11 03 d7 03 c2 25 ff 00 00 00 8b f8 8a 14 37 8a 01 88 04 37 } //01 00 
		$a_03_3 = {74 17 8a 46 01 80 e9 90 01 01 46 84 c0 74 33 2c 90 01 01 b3 90 01 01 f6 eb 02 c8 8b 44 24 90 01 01 8b 5c 24 90 01 01 2a ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_16{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 57 ff 15 90 01 04 85 c0 74 90 01 01 8b 4c 24 10 6a 04 68 00 10 00 00 51 56 ff d0 8b f8 eb 02 33 ff 8b 4c 24 10 8b d1 c1 e9 02 33 c0 89 7b f8 f3 ab 90 00 } //01 00 
		$a_01_1 = {8a 0f 84 c9 74 15 2a 0a 46 88 4e ff 8a 4a 01 42 84 c9 75 02 8b d5 47 3b fb 72 e5 } //01 00 
		$a_03_2 = {84 c0 74 14 8b 0d 90 01 04 68 90 01 04 e8 90 01 04 85 c0 75 08 b8 01 00 00 00 c2 04 00 ff e0 90 00 } //01 00 
		$a_00_3 = {42 49 4e 00 53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_17{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c1 8d a4 24 00 00 00 00 8a 50 01 40 84 d2 75 90 01 01 2d 90 00 } //01 00 
		$a_02_1 = {50 8b f0 ff d7 8d 0c 30 8d 80 90 01 04 3d 90 01 04 72 90 01 01 2b c8 eb 90 01 01 8d 49 00 90 00 } //01 00 
		$a_02_2 = {f7 d8 1b c0 83 e0 07 40 f7 c3 00 00 00 04 74 90 01 01 0d 00 02 00 00 90 00 } //01 00 
		$a_01_3 = {74 31 0f be c0 83 e8 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02 } //01 00 
		$a_03_4 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 90 01 04 5f 5e 5b c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_18{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d0 0f be c9 8a 89 90 01 04 88 08 8a 4c 02 01 40 84 c9 90 00 } //01 00 
		$a_03_1 = {83 f8 07 75 90 01 02 40 00 00 00 90 02 42 33 c9 83 f8 90 01 01 0f 95 c1 49 83 e1 90 00 } //01 00 
		$a_03_2 = {8a c2 2a c3 88 90 02 02 8a 90 01 01 01 90 01 02 84 c0 90 00 } //01 00 
		$a_00_3 = {8b 4c 24 08 8a 10 88 11 41 40 3b c6 } //01 00 
		$a_00_4 = {8b 51 28 6a 00 6a 00 50 03 d0 ff d2 c6 05 } //02 00 
		$a_03_5 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f 90 02 20 01 00 00 00 09 00 00 00 09 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_19{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec 80 02 00 00 90 02 05 8b 15 90 01 01 72 40 00 90 00 } //01 00 
		$a_03_1 = {55 8b ec 81 ec 80 02 00 00 0f b6 90 01 01 a8 72 40 00 85 90 01 01 74 90 00 } //02 00 
		$a_03_2 = {c7 05 a0 72 40 00 00 00 00 00 90 03 01 01 eb e9 90 00 } //01 00 
		$a_03_3 = {a1 a4 72 40 00 0f be 08 83 f9 22 75 90 01 01 8b 0d a4 72 40 00 83 c1 01 90 00 } //01 00 
		$a_03_4 = {f7 d9 ff 24 8d 90 01 02 40 00 8d 49 00 8b c7 ba 03 00 00 00 83 f9 04 72 90 01 01 83 e0 03 2b c8 ff 24 85 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_20{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 00 8b 55 10 52 e8 90 01 02 ff ff 83 c4 08 90 00 } //02 00 
		$a_03_1 = {a8 72 40 00 85 90 01 01 74 90 01 01 83 7d 0c 00 75 09 90 01 01 01 00 00 00 85 90 01 01 74 09 8b 90 01 01 0c 89 90 01 01 a0 72 40 00 e9 90 00 } //01 00 
		$a_03_2 = {8b 76 0c 81 e6 ff 7f 00 00 89 35 90 01 04 83 f9 02 74 90 01 01 81 ce 00 80 00 00 89 35 90 01 04 c1 e0 08 03 c2 a3 90 01 04 33 f6 56 8b 3d 90 01 04 ff 90 00 } //01 00 
		$a_01_3 = {8b 15 a4 72 40 00 0f be 02 85 c0 75 } //01 00 
		$a_01_4 = {8b 0d a4 72 40 00 0f be 11 85 d2 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_21{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0b 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b 55 dc 81 3a 50 45 00 00 74 } //03 00 
		$a_01_1 = {8b 55 dc 81 3a 50 45 00 00 0f } //01 00 
		$a_01_2 = {5d 3e 5d 3e 5d 3e 5d 3e } //01 00 
		$a_03_3 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 90 02 04 4c 6f 63 6b 52 65 73 6f 75 72 63 65 90 02 04 4c 6f 61 64 52 65 73 6f 75 72 63 65 90 02 04 46 69 6e 64 52 65 73 6f 75 72 63 65 41 90 00 } //05 00 
		$a_01_4 = {00 42 49 4e 00 } //05 00 
		$a_03_5 = {74 23 6a 04 68 00 20 00 00 8b 85 90 01 02 ff ff 50 8b 8d 90 01 02 ff ff 51 ff 95 90 01 02 ff ff 89 85 90 01 02 ff ff eb 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_22{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 70 74 61 67 3d 00 } //01 00 
		$a_01_1 = {26 70 61 72 74 6e 65 72 3d 00 } //01 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 2f 3f 25 73 3d 25 64 00 } //01 00 
		$a_03_3 = {8d 44 24 10 81 c6 90 01 02 00 00 50 8b ce c7 44 24 14 90 01 04 e8 90 01 04 8d 4c 24 10 51 8b ce c7 44 24 14 90 01 04 e8 90 01 04 8d 54 24 10 90 00 } //01 00 
		$a_03_4 = {8b 59 04 85 db c7 44 24 18 00 00 00 00 75 04 33 c0 eb 18 8b 71 08 2b f3 b8 90 01 04 f7 ee 03 d6 c1 fa 04 8b c2 c1 e8 1f 03 c2 8b 7c 24 20 3b c7 73 33 85 db 75 04 33 c0 eb 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_23{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,38 00 33 00 08 00 00 32 00 "
		
	strings :
		$a_00_0 = {c0 e0 02 8b d5 c1 fa 04 0a d0 } //05 00 
		$a_01_1 = {66 61 6d 69 6c 69 65 00 66 61 6d 69 6c 6c 65 00 66 61 6d 69 6c 79 00 66 69 6e 64 00 66 72 65 65 00 67 61 6d 65 } //05 00 
		$a_03_2 = {70 76 65 72 3d 90 02 04 26 61 6d 3d 90 02 04 26 61 75 3d 90 00 } //01 00 
		$a_11_3 = {75 6d 69 65 01 } //00 0c 
		$a_62_4 = {6f 77 73 65 72 71 75 65 73 74 01 00 0a 11 6b 65 65 } //6e 66 
		$a_6e_5 = {65 72 05 00 24 03 63 68 65 63 6b 75 70 64 90 02 04 73 6c 6f 61 64 90 02 04 74 62 68 69 64 65 90 02 04 74 62 73 68 6f 77 90 00 01 00 07 11 53 65 65 6b 65 65 6e 00 00 78 b6 00 00 03 00 03 00 06 00 00 01 00 23 03 28 83 40 00 83 90 01 01 01 89 90 01 01 28 83 40 00 8b 90 01 01 28 83 40 00 89 90 01 01 20 83 40 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_24{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 83 40 00 83 90 01 01 01 89 90 01 01 28 83 40 00 8b 90 01 01 28 83 40 00 89 90 01 01 20 83 40 00 90 00 } //01 00 
		$a_03_1 = {28 83 40 00 83 90 01 01 01 90 01 01 28 83 40 00 8b 90 01 01 28 83 40 00 89 90 01 01 20 83 40 00 90 00 } //01 00 
		$a_03_2 = {28 83 40 00 83 90 01 01 01 89 90 01 01 28 83 40 00 90 01 01 28 83 40 00 90 01 01 20 83 40 00 90 00 } //01 00 
		$a_01_3 = {c7 05 20 83 40 00 00 00 00 00 } //01 00 
		$a_01_4 = {c7 05 28 83 40 00 00 00 00 00 } //01 00 
		$a_03_5 = {30 80 40 00 88 90 09 0b 00 8b 90 01 01 fc 0f be 90 01 01 8b 90 01 01 f8 8a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_25{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c1 8d a4 24 00 00 00 00 8a 50 01 40 84 d2 75 90 01 01 2d 90 00 } //01 00 
		$a_00_1 = {8b 54 24 08 8a 0a 33 f6 84 c9 74 0c 0f b6 c9 42 03 f1 8a 0a 84 c9 75 f4 8b c8 8a 00 33 d2 84 c0 } //01 00 
		$a_03_2 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 90 01 04 5f 5e 5b c9 c3 90 00 } //01 00 
		$a_03_3 = {3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7 90 09 0f 00 04 90 03 01 01 e0 20 80 f9 90 03 01 01 61 41 7c 08 80 f9 90 03 01 01 7a 5a 7f 03 80 c1 90 03 01 01 e0 20 90 00 } //01 00 
		$a_01_4 = {80 38 2d 89 74 24 08 74 0c 8b 06 8b 48 7c 83 c0 78 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_26{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 44 24 08 8b 4c 24 04 f6 d8 55 56 57 1b c0 25 90 01 04 05 90 01 04 8d 6c 08 ff 3b cd be 90 01 04 bf 90 01 04 73 48 53 90 00 } //01 00 
		$a_03_1 = {33 c9 83 f8 06 0f 95 c1 49 83 e1 c4 83 c1 40 8b c1 f7 90 01 01 00 00 00 04 90 00 } //01 00 
		$a_03_2 = {56 8b f1 57 8b 3e 85 ff 74 90 01 01 68 90 01 04 e8 90 01 04 83 c4 04 50 8b 06 50 ff 15 90 01 04 85 c0 74 90 01 01 57 ff d0 5f 5e c3 90 00 } //01 00 
		$a_03_3 = {0f be c0 83 e8 61 b3 1a f6 eb 90 02 04 02 c2 2c 61 41 eb 02 90 00 } //01 00 
		$a_03_4 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 90 01 04 5f 5e 5b c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_27{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 0e 8b 4c 24 08 8a 10 88 11 41 40 3b c6 75 f6 } //01 00 
		$a_03_1 = {8a 01 84 c0 75 90 01 01 8a 02 33 c9 84 c0 74 90 01 01 8d a4 24 00 00 00 00 0f b6 c0 42 8d 8c 01 90 01 04 8a 02 84 c0 75 90 01 01 33 c0 3b f1 0f 94 c0 5e 90 00 } //01 00 
		$a_00_2 = {8b 51 28 6a 00 6a 00 50 03 d0 ff d2 c6 05 } //01 00 
		$a_03_3 = {ff d0 c2 04 00 90 02 0b 68 90 01 04 e8 90 01 04 83 c4 04 84 c0 75 06 b8 01 00 00 00 c3 68 90 01 04 e8 90 01 04 83 c4 04 85 c0 75 06 b8 02 00 00 00 c3 ff e0 90 00 } //01 00 
		$a_03_4 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f 90 02 17 01 00 00 00 09 00 00 00 09 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_28{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 e0 02 00 00 00 8b 55 0c 8b 42 04 89 45 e8 8b 4d e8 89 4d f0 8b 55 f0 89 55 e4 8b 45 e0 8b 4d e4 8d 14 81 89 55 e4 8b 45 e4 89 45 ec 8b 4d ec 8b 11 52 ff 55 08 e9 15 01 00 00 } //01 00 
		$a_03_1 = {8b 4d cc 0f be 11 83 fa 2d 0f 85 90 01 02 00 00 8b 45 cc 0f be 48 01 83 f9 78 0f 85 90 01 02 00 00 8b 55 cc 0f be 42 02 83 f8 72 0f 85 90 01 02 00 00 90 00 } //01 00 
		$a_03_2 = {6a 00 6a 00 8b 55 c8 52 ff 15 90 01 04 89 45 d4 90 00 } //01 00 
		$a_03_3 = {8b 4d cc 0f be 11 83 fa 2d 0f 85 90 01 02 00 00 8b 45 cc 0f be 48 01 83 f9 78 0f 85 90 01 02 00 00 8b 55 cc 0f be 42 02 83 f8 72 0f 85 90 01 02 00 00 8b 4d cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_29{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 0f 84 c9 74 15 2a 0a 46 88 4e ff 8a 4a 01 42 84 c9 75 02 8b d5 47 3b fb 72 e5 } //05 00 
		$a_03_1 = {84 c0 74 14 8b 0d 90 01 02 00 10 68 90 01 02 00 10 e8 90 01 02 ff ff 85 c0 75 08 b8 01 00 00 00 c2 04 00 ff e0 90 09 05 00 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_03_2 = {eb 02 33 c9 68 90 01 02 00 10 89 0d 04 90 01 01 00 10 89 5d fc e8 90 01 02 ff ff 3b c3 74 36 90 00 } //01 00 
		$a_03_3 = {74 16 8b 0d 90 01 02 00 10 68 90 01 02 00 10 e8 90 01 02 ff ff 85 c0 74 02 ff e0 33 c0 c2 0c 00 90 00 } //01 00 
		$a_03_4 = {c7 44 24 14 ff ff ff ff 74 21 6a 00 6a 00 68 10 a1 00 10 68 90 01 01 a1 00 10 e8 6f 03 00 00 83 c4 10 50 56 ff d7 85 c0 74 03 56 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_30{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 76 0c 81 e6 ff 7f 00 00 89 35 90 01 04 83 f9 02 74 90 01 01 81 ce 00 80 00 00 89 35 90 01 04 c1 e0 08 03 c2 a3 90 01 04 33 f6 56 8b 3d 90 01 04 ff 90 00 } //01 00 
		$a_03_1 = {0f be 02 83 f8 20 74 90 01 01 8b 0d 90 01 04 0f be 11 83 fa 09 90 01 02 8b 15 90 01 04 83 c2 01 89 15 90 01 04 eb 90 00 } //01 00 
		$a_03_2 = {0f be 08 83 f9 20 74 90 01 01 8b 15 90 01 04 0f be 02 83 f8 09 90 01 02 a1 90 01 04 83 c0 01 a3 90 01 04 eb 90 00 } //01 00 
		$a_03_3 = {0f be 11 83 fa 20 74 90 01 01 a1 90 01 04 0f be 08 83 f9 09 90 01 02 8b 0d 90 01 04 83 c1 01 89 0d 90 01 04 eb 90 00 } //02 00 
		$a_03_4 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 90 01 04 5f 5e 5b c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_31{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6d 64 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 32 20 26 26 20 64 65 6c 20 22 } //01 00 
		$a_00_1 = {2f 69 6e 73 74 61 6c 6c 2e 61 73 70 78 3f 62 3d 62 61 73 69 63 73 63 61 6e 26 64 3d 6f 70 73 64 65 76 } //01 00 
		$a_01_2 = {52 4f 4f 54 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 00 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 00 57 51 4c 00 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //01 00 
		$a_01_3 = {41 56 20 74 6f 6f 6c 73 3a 20 25 64 0a 00 41 53 20 74 6f 6f 6c 73 3a 20 25 64 0a 00 2d 20 6e 61 6d 65 3a 20 25 73 0a 20 20 63 6f 6d 70 61 6e 79 3a 20 25 73 0a 20 20 76 65 72 73 69 6f 6e 3a 20 25 73 0a 20 20 65 6e 61 62 6c 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_32{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 45 f8 8b 4d fc 90 01 03 89 4d f4 6a 00 6a 00 6a 01 68 90 01 04 e8 90 01 04 83 c4 10 50 ff 15 90 00 } //01 00 
		$a_03_1 = {73 21 8b 4d 90 01 01 0f be 11 83 fa 20 74 0b 8b 45 90 01 01 0f be 08 83 f9 09 75 0b 90 00 } //01 00 
		$a_03_2 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 90 01 04 5f 5e 5b c9 c3 90 00 } //01 00 
		$a_03_3 = {f7 d9 ff 24 8d 90 01 02 40 00 8d 49 00 8b c7 ba 03 00 00 00 83 f9 04 72 90 01 01 83 e0 03 2b c8 ff 24 85 90 01 02 40 00 90 00 } //01 00 
		$a_03_4 = {8d 34 40 8d 34 90 01 03 40 00 2b d0 83 26 00 83 c6 0c 4a 75 90 01 01 8b 09 81 f9 8e 00 00 c0 8b 90 01 03 40 00 75 90 01 01 c7 05 90 01 02 40 00 83 00 00 00 eb 90 01 01 81 f9 90 90 00 00 c0 75 90 01 01 c7 05 90 01 02 40 00 81 00 00 00 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_33{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 45 78 74 65 6e 73 69 6f 6e 73 } //0a 00 
		$a_00_1 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //0a 00 
		$a_00_2 = {3c 55 72 6c 20 74 79 70 65 3d 22 74 65 78 74 2f 68 74 6d 6c 22 20 6d 65 74 68 6f 64 3d 22 47 45 54 22 20 74 65 6d 70 6c 61 74 65 3d 22 } //01 00 
		$a_03_3 = {3c 53 68 6f 72 74 4e 61 6d 65 3e 4b 77 90 03 01 01 69 61 6e 7a 79 3c 2f 53 68 6f 72 74 4e 61 6d 65 3e 90 00 } //01 00 
		$a_00_4 = {3c 53 68 6f 72 74 4e 61 6d 65 3e 5a 77 75 6e 7a 69 3c 2f 53 68 6f 72 74 4e 61 6d 65 3e } //01 00 
		$a_00_5 = {3c 53 68 6f 72 74 4e 61 6d 65 3e 46 69 6e 64 42 61 73 69 63 3c 2f 53 68 6f 72 74 4e 61 6d 65 3e } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_34{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {c7 05 a0 72 40 00 00 00 00 00 90 03 01 01 eb e9 90 00 } //01 00 
		$a_01_1 = {a1 a8 72 40 00 0f be 08 85 c9 75 0c c7 05 a8 72 40 00 00 00 00 00 eb 16 } //01 00 
		$a_01_2 = {a1 a4 72 40 00 0f be 08 85 c9 75 0c c7 05 a4 72 40 00 00 00 00 00 eb 16 } //01 00 
		$a_03_3 = {0f be 11 85 d2 75 0c c7 05 90 03 01 01 a4 a8 72 40 00 00 00 00 00 eb 17 90 09 0f 00 8b 0d 90 03 01 01 a4 a8 72 40 00 90 00 } //01 00 
		$a_03_4 = {0f be 02 85 c0 75 0c c7 05 90 03 01 01 a4 a8 72 40 00 00 00 00 00 eb 18 90 09 0f 00 8b 15 90 03 01 01 a4 a8 72 40 00 90 00 } //01 00 
		$a_03_5 = {0f be 11 85 d2 75 1d eb 0f 90 09 06 00 8b 0d 90 03 01 01 a4 a8 72 40 00 90 00 } //01 00 
		$a_03_6 = {a4 72 40 00 0f be 90 01 01 85 90 01 01 75 0c c7 05 a4 72 40 00 ff ff ff ff eb 90 00 } //01 00 
		$a_03_7 = {83 3d a0 72 40 00 00 75 0a c7 05 a4 72 40 00 00 00 00 00 90 03 01 01 eb e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_35{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 45 f8 8b 4d fc 03 4d f8 89 4d f4 6a 00 6a 00 6a 01 68 90 01 04 e8 90 01 04 83 c4 10 50 ff 15 90 00 } //01 00 
		$a_03_1 = {8b 4d 18 51 8b 55 14 52 8b 45 10 50 8b 4d 0c 51 8b 55 08 52 ff 55 90 01 01 89 45 90 01 01 eb 90 00 } //01 00 
		$a_01_2 = {33 45 10 8b 4d fc 89 01 8b 55 fc 83 c2 04 89 55 fc } //01 00 
		$a_00_3 = {89 45 e8 8b 4d ec 03 4d e8 89 4d e4 8b 55 0c 8b 45 0c 8b 4a 28 2b 48 2c 89 4d fc } //01 00 
		$a_00_4 = {89 45 bc 8b 4d fc 8b 55 ac 8b 01 33 42 04 8b 4d fc 89 01 8b 55 fc 83 c2 04 89 55 fc } //01 00 
		$a_03_5 = {8d 34 40 8d 34 90 01 03 40 00 2b d0 83 26 00 83 c6 0c 4a 75 90 01 01 8b 09 81 f9 8e 00 00 c0 8b 90 01 03 40 00 75 90 01 01 c7 05 90 01 02 40 00 83 00 00 00 eb 90 01 01 81 f9 90 90 00 00 c0 75 90 01 01 c7 05 90 01 02 40 00 81 00 00 00 eb 90 00 } //01 00 
		$a_03_6 = {53 ff d0 8b d8 ff 75 10 ff 75 0c ff 75 08 53 ff 15 90 01 04 5f 5e 5b c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_36{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 19 8b 55 fc 0f be 02 0f be 4d fb 3b c1 74 0b } //01 00 
		$a_01_1 = {74 19 8b 45 fc 0f be 08 0f be 55 fb 3b ca 74 0b } //01 00 
		$a_01_2 = {74 19 8b 4d fc 0f be 11 0f be 45 fb 3b d0 74 0b } //01 00 
		$a_03_3 = {c7 85 d4 fe ff ff 00 00 00 00 eb 0f 90 01 0f 83 bd d4 fe ff ff 04 0f 8d 90 01 01 00 00 00 90 00 } //01 00 
		$a_03_4 = {c7 45 dc 00 00 00 00 eb 09 90 01 09 83 7d dc 04 0f 8d 90 01 01 00 00 00 90 00 } //01 00 
		$a_03_5 = {c7 45 d8 00 00 00 00 eb 09 90 01 09 83 7d d8 04 0f 8d 90 01 01 00 00 00 90 00 } //01 00 
		$a_03_6 = {83 bd d4 fe ff ff 03 75 90 03 01 01 09 0c 8b 90 17 03 01 01 01 55 45 4d f0 90 17 03 01 01 01 52 50 51 ff 55 e0 90 00 } //01 00 
		$a_03_7 = {83 7d dc 03 75 90 03 01 01 09 0c 8b 90 17 03 01 01 01 55 45 4d f0 90 17 03 01 01 01 52 50 51 ff 55 e0 90 00 } //01 00 
		$a_03_8 = {83 7d d8 03 75 90 03 01 01 09 0c 8b 90 17 03 01 01 01 55 45 4d f0 90 17 03 01 01 01 52 50 51 ff 55 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_37{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 8b 00 8b 4d 08 8b 55 f0 03 44 8a 08 } //05 00 
		$a_01_1 = {8b 55 f0 8b 02 8b 55 f0 03 44 8a 08 } //05 00 
		$a_03_2 = {8b 55 08 8b 45 90 01 01 8b 4c 90 90 08 89 4d 90 01 1f 90 03 03 00 90 01 1e 8b 55 90 01 01 8b 02 03 45 90 00 } //05 00 
		$a_01_3 = {8b 45 fc 8b 08 33 4d 10 8b 55 fc 89 0a } //01 00 
		$a_03_4 = {50 ff 55 08 90 09 20 00 6a 90 03 01 01 04 02 8b 4d 0c e8 90 01 04 50 6a 90 03 01 01 03 01 8b 4d 0c e8 90 01 04 50 6a 90 03 01 01 02 00 8b 4d 0c e8 90 00 } //05 00 
		$a_03_5 = {6b c0 61 99 b9 29 e5 0a 00 f7 f9 89 55 fc 90 01 1e 90 03 03 00 90 01 1e 8b 55 90 01 01 8b 02 69 c0 56 05 00 00 05 73 4d 02 00 90 00 } //01 00 
		$a_03_6 = {8a 08 88 0a 8b 55 90 01 01 83 c2 01 89 55 90 01 01 8b 45 90 01 01 83 c0 01 89 45 90 01 1f 90 03 03 00 90 01 1e eb 90 00 } //01 00 
		$a_03_7 = {8a 11 88 10 8b 45 90 01 01 83 c0 01 89 45 90 01 01 8b 4d 90 01 01 83 c1 01 89 4d 90 01 1f 90 03 03 00 90 01 1e eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_38{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0a 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 43 4c 49 45 4e 54 } //02 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 5a 75 6d 69 65 } //02 00 
		$a_01_2 = {63 68 65 63 6b 75 70 64 } //02 00 
		$a_01_3 = {43 6f 70 79 72 69 67 68 74 20 28 63 29 20 32 30 30 37 20 5a 75 6d 69 65 2e 63 6f 6d } //02 00 
		$a_01_4 = {5a 75 6d 69 65 20 4f 70 74 69 6f 6e 73 20 50 61 6e 65 6c } //02 00 
		$a_01_5 = {42 6c 69 6e 6b 20 4f 70 74 69 6f 6e 73 20 50 61 6e 65 6c 20 69 73 20 61 6c 72 65 61 64 79 20 72 75 6e 6e 69 6e 67 21 } //02 00 
		$a_01_6 = {62 6c 69 6e 6b 6f 70 74 2e 70 64 62 } //02 00 
		$a_01_7 = {5a 00 75 00 6d 00 69 00 65 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 65 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_39{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 0b 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 54 81 08 90 09 2a 00 03 51 2c 89 55 90 00 } //01 00 
		$a_03_1 = {8b 54 81 08 90 09 48 00 03 51 2c 89 55 90 00 } //01 00 
		$a_03_2 = {03 51 2c 89 55 90 01 22 83 c0 08 90 01 27 8d 04 8a 90 00 } //01 00 
		$a_03_3 = {03 51 2c 89 55 90 01 43 83 c0 08 90 01 27 8d 04 8a 90 00 } //01 00 
		$a_03_4 = {89 44 91 08 8b 95 90 01 04 8b 42 28 90 09 11 00 2b 02 90 00 } //01 00 
		$a_03_5 = {8b 51 28 8b 85 90 01 0a 89 4c 90 90 08 90 01 33 8b 42 28 90 09 3b 00 2b 02 90 00 } //01 00 
		$a_03_6 = {8b 51 28 8b 85 90 01 0a 89 4c 90 90 08 90 01 33 8b 42 28 90 09 68 00 2b 02 90 00 } //01 00 
		$a_03_7 = {c7 42 28 00 00 00 00 90 01 2d 8b 85 90 01 04 83 78 28 08 0f 8d 90 09 06 00 8b 95 90 00 } //01 00 
		$a_03_8 = {c7 42 28 00 00 00 00 90 01 5a 8b 85 90 01 04 83 78 28 08 0f 8d 90 09 06 00 8b 95 90 00 } //01 00 
		$a_03_9 = {33 4d 10 8b 55 90 01 01 89 0a 8b 45 90 01 01 83 c0 04 89 45 90 01 1f eb 90 00 } //01 00 
		$a_03_10 = {33 4d 10 8b 55 90 01 01 89 0a 8b 45 90 01 01 83 c0 04 89 45 90 01 3d eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_40{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 fa 2d 0f 85 90 01 31 90 03 03 00 90 01 2d 8b 45 90 01 01 0f be 48 02 83 f9 72 0f 85 90 01 31 90 03 03 00 90 01 2d 8b 55 90 01 01 0f be 42 01 83 f8 78 0f 85 90 00 } //01 00 
		$a_03_1 = {83 f8 2d 0f 85 90 01 31 90 03 03 00 90 01 2d 8b 4d 90 01 01 0f be 51 02 83 fa 72 0f 85 90 01 31 90 03 03 00 90 01 2d 8b 45 90 01 01 0f be 48 01 83 f9 78 0f 85 90 00 } //01 00 
		$a_03_2 = {83 f8 78 0f 85 90 01 31 90 03 03 00 90 01 2d 8b 4d 90 01 01 0f be 51 02 83 fa 72 0f 85 90 00 } //01 00 
		$a_03_3 = {83 f9 2d 0f 85 90 01 31 90 03 03 00 90 01 2d 8b 55 90 01 01 8a 42 01 88 85 90 01 31 90 03 03 00 90 01 2d 0f be 8d 90 01 04 83 f9 72 0f 85 90 00 } //01 00 
		$a_03_4 = {83 f9 78 0f 85 90 01 31 90 03 03 00 90 01 2d 8b 55 90 01 01 8a 42 02 88 85 90 01 31 90 03 03 00 90 01 2d 0f be 8d 90 01 04 83 f9 72 0f 85 90 00 } //64 00 
		$a_03_5 = {6b c0 61 99 b9 29 e5 0a 00 f7 f9 89 55 fc 90 01 1e 90 03 03 00 90 01 1e 8b 55 90 01 01 8b 02 69 c0 56 05 00 00 05 73 4d 02 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_41{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 11 88 55 90 01 01 90 03 03 00 90 01 1e 90 03 03 00 90 01 1e 8b 45 90 01 01 83 c0 01 89 45 90 01 1f 90 03 03 00 90 01 1e 0f be 4d 90 01 01 85 c9 90 03 01 01 74 75 90 00 } //01 00 
		$a_03_1 = {8a 11 88 55 90 01 01 90 03 03 00 90 01 1e 90 03 03 00 90 01 1e 8b 45 90 01 01 8b 08 83 c1 01 8b 55 90 01 01 89 0a 90 01 1e 90 03 03 00 90 01 1e 8a 45 90 00 } //01 00 
		$a_03_2 = {8a 08 88 4d 90 01 01 8b 55 90 01 01 83 c2 01 89 55 90 01 1f 90 03 03 00 90 01 1e 0f be 45 90 01 01 85 c0 90 17 03 02 02 02 74 08 75 41 75 23 90 00 } //01 00 
		$a_03_3 = {8a 08 88 0a 8b 55 90 01 01 83 c2 01 89 55 90 01 01 8b 45 90 01 01 83 c0 01 89 45 90 01 1f 90 03 03 00 90 01 1e eb 90 00 } //01 00 
		$a_03_4 = {83 c0 01 2b 45 90 01 01 8b 4d 90 01 01 2b c8 89 4d 90 01 2e 90 03 03 00 90 01 2d 8b 55 90 01 01 83 c2 01 89 55 90 00 } //64 00 
		$a_03_5 = {6b c0 61 99 b9 29 e5 0a 00 f7 f9 89 55 fc 90 01 1e 90 03 03 00 90 01 1e 8b 55 90 01 01 8b 02 69 c0 56 05 00 00 05 73 4d 02 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_42{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 0a 00 00 64 00 "
		
	strings :
		$a_01_0 = {04 e0 80 f9 61 7c 08 80 f9 7a 7f 03 80 c1 e0 3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7 33 d2 3a c1 0f 94 c2 8a c2 5e c3 } //0a 00 
		$a_03_1 = {66 81 3e 4d 5a c6 44 24 18 01 74 0c 68 90 01 04 8b cf e8 90 01 04 53 8b 5e 3c 8b 04 33 03 de 3d 50 45 00 00 74 0c 90 00 } //05 00 
		$a_03_2 = {4d 5a c6 44 24 90 01 02 74 90 09 03 00 66 81 90 00 } //05 00 
		$a_01_3 = {57 8b 7e 3c 8b 04 37 03 fe 3d 50 45 00 00 89 7c 24 10 74 1e } //05 00 
		$a_01_4 = {53 8b 5e 3c 8b 04 33 03 de 3d 50 45 00 00 74 1e } //05 00 
		$a_01_5 = {55 8b 68 3c 03 e8 81 7d 00 50 45 00 00 74 1d } //05 00 
		$a_01_6 = {57 8b 78 3c 03 f8 81 3f 50 45 00 00 75 35 } //01 00 
		$a_03_7 = {74 17 8a 46 01 80 e9 90 01 01 46 84 c0 74 33 2c 90 01 01 b3 90 01 01 f6 eb 02 c8 8b 44 24 90 01 01 8b 5c 24 90 01 01 2a ca 90 00 } //01 00 
		$a_03_8 = {0f 94 c0 84 c0 74 1d e8 90 01 04 84 c0 74 14 8b 0d 90 01 04 68 90 01 04 e8 90 01 04 85 c0 75 09 90 09 04 00 75 ee 3a 90 00 } //01 00 
		$a_03_9 = {b9 09 00 00 00 33 c0 f3 a6 5f 5e 75 1f e8 90 01 04 84 c0 74 16 8b 0d 90 01 04 68 90 01 04 e8 90 01 04 85 c0 74 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_43{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 10 00 00 01 00 "
		
	strings :
		$a_01_0 = {c3 83 f8 05 75 06 b8 80 00 00 00 c3 3d } //01 00 
		$a_01_1 = {c3 83 f8 03 1b c0 83 e0 e2 05 } //01 00 
		$a_01_2 = {0f b7 51 14 33 c4 89 44 24 04 8b 44 24 10 53 33 db 66 39 59 06 89 44 24 04 8d 44 0a 18 } //01 00 
		$a_01_3 = {33 f6 66 8b 33 8b ce 81 e1 ff 0f 00 00 03 c8 f7 c6 00 f0 00 00 74 14 } //01 00 
		$a_01_4 = {8b c8 25 ff 0f 00 00 c1 e9 0c 03 c6 85 c9 8b f0 74 2f } //01 00 
		$a_01_5 = {03 c1 8b 4f 04 83 e9 08 33 ed f7 c1 fe ff ff ff 8d 5f 08 } //01 00 
		$a_01_6 = {8b 5e 24 55 57 8b 7e 20 03 f9 03 d9 33 ed 85 c0 } //01 00 
		$a_01_7 = {8b 4c 24 08 8b 54 24 0c 56 8b 74 24 08 8d 04 11 03 f2 3b c1 74 0d 2b f0 8a 50 ff 48 3b c1 88 14 06 75 f5 } //01 00 
		$a_01_8 = {03 d6 3b c1 74 15 8b f2 2b f0 3b c1 77 02 73 07 8a 50 ff 48 88 14 06 3b c1 75 f1 } //01 00 
		$a_01_9 = {77 02 73 0c 85 f6 7e 08 8a 50 ff 48 88 14 07 46 3b c1 75 ec } //01 00 
		$a_01_10 = {74 13 77 02 73 0b 48 85 f6 7e 06 8a 10 4f 88 17 46 3b c1 75 ed } //01 00 
		$a_01_11 = {74 16 77 02 73 0e 85 c9 74 0a 48 85 f6 74 05 8a 10 4e 88 16 3b c1 75 ea } //01 00 
		$a_01_12 = {77 02 73 0b 85 c9 74 07 8a 50 ff 48 88 14 06 3b c1 75 ed } //01 00 
		$a_03_13 = {2b d0 0f be c9 8a 89 90 01 04 88 08 8a 4c 02 01 40 84 c9 75 ec c6 00 00 90 00 } //01 00 
		$a_03_14 = {8d 64 24 00 0f be d2 8a 92 90 01 04 88 11 8a 54 0e 01 41 84 d2 75 ec c6 01 00 90 00 } //01 00 
		$a_01_15 = {8d 04 82 8b 04 08 5f 03 c1 5d d1 e0 5b d1 e8 5e } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_44{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 17 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 03 45 08 2b 45 f0 33 45 f4 89 45 f4 } //01 00 
		$a_01_1 = {8b 55 f0 03 55 08 2b 55 f0 33 55 f4 89 55 f4 } //01 00 
		$a_01_2 = {8b 4d f0 03 4d 08 2b 4d f0 33 4d f4 89 4d f4 } //01 00 
		$a_01_3 = {0f be 55 f3 2b 55 f4 03 55 ec 89 55 ec } //01 00 
		$a_01_4 = {0f be 45 f3 2b 45 f4 03 45 ec 89 45 ec } //01 00 
		$a_01_5 = {0f be 4d f3 2b 4d f4 03 4d ec 89 4d ec } //01 00 
		$a_01_6 = {0f be 55 ef 2b 55 f0 03 55 e8 89 55 e8 } //01 00 
		$a_01_7 = {0f be 45 ef 2b 45 f0 03 45 e8 89 45 e8 } //01 00 
		$a_01_8 = {0f be 4d ef 2b 4d f0 03 4d e8 89 4d e8 } //01 00 
		$a_03_9 = {8b 45 08 8a 08 88 4d 90 01 01 0f be 55 90 01 01 8b 45 08 83 c0 01 89 45 08 90 00 } //01 00 
		$a_01_10 = {75 02 eb 10 eb e7 } //01 00 
		$a_01_11 = {75 02 eb 2a eb 19 } //01 00 
		$a_01_12 = {75 02 eb 10 eb da } //01 00 
		$a_01_13 = {75 02 eb 04 eb e7 } //01 00 
		$a_01_14 = {eb d1 eb 4b eb 3b } //01 00 
		$a_03_15 = {83 f9 22 75 02 eb 90 01 01 eb 90 09 04 00 0f be 4d 90 00 } //01 00 
		$a_03_16 = {83 f8 22 75 02 eb 90 01 01 eb 90 09 04 00 0f be 45 90 00 } //01 00 
		$a_03_17 = {83 fa 22 75 02 eb 90 01 01 eb 90 09 04 00 0f be 55 90 00 } //01 00 
		$a_03_18 = {0f be 02 83 f8 22 75 5a eb 90 01 01 eb 90 00 } //01 00 
		$a_03_19 = {0f be 08 83 f9 22 75 51 eb 90 01 01 eb 90 00 } //01 00 
		$a_01_20 = {eb c7 eb bb eb 08 } //01 00 
		$a_03_21 = {75 0c c7 05 28 83 40 00 00 00 00 00 eb 90 09 09 00 28 83 40 00 0f be 90 01 01 85 90 00 } //01 00 
		$a_03_22 = {89 4d f4 8b 55 90 01 01 83 3a 00 74 90 09 22 00 89 4d 90 1b 00 c7 45 fc 90 01 04 c7 45 f8 90 01 04 8b 45 f8 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_45{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 18 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 16 2a c2 88 07 8a 46 01 } //01 00 
		$a_01_1 = {8a c2 2a c3 88 45 00 8a 47 01 } //01 00 
		$a_01_2 = {8b 70 04 8b 0c 30 03 c6 85 c9 77 f4 8b 02 } //01 00 
		$a_01_3 = {8a 51 03 8a c3 32 d0 88 51 03 } //01 00 
		$a_01_4 = {74 0e 8b 4c 24 08 8a 10 88 11 41 40 3b c6 75 f6 } //01 00 
		$a_01_5 = {2b f0 8a 50 ff 48 3b c1 88 14 06 77 f5 } //01 00 
		$a_01_6 = {03 f7 8a 41 ff 49 3b ca 88 04 0e 75 f5 } //01 00 
		$a_01_7 = {8a 50 ff 48 88 14 06 3b c1 75 f1 } //01 00 
		$a_01_8 = {8a 50 ff 48 88 14 07 46 3b c1 75 ec } //01 00 
		$a_01_9 = {8a 50 ff 48 88 14 07 3b c1 75 e9 } //01 00 
		$a_01_10 = {83 f8 05 75 07 b8 80 00 00 00 eb 11 33 c9 83 f8 06 0f 95 c1 49 } //01 00 
		$a_01_11 = {83 f8 05 75 06 b8 80 00 00 00 c3 33 c9 83 f8 06 0f 95 c1 49 } //01 00 
		$a_01_12 = {83 f8 06 75 06 b8 04 00 00 00 c3 33 c9 83 f8 07 0f 95 c1 49 83 e1 40 } //01 00 
		$a_01_13 = {83 f8 05 75 07 b8 80 00 00 00 eb 11 33 d2 83 f8 06 0f 95 c2 4a } //01 00 
		$a_01_14 = {83 f8 05 75 06 b8 80 00 00 00 c3 } //01 00 
		$a_03_15 = {c3 83 f8 03 75 06 b8 90 01 04 c3 3d 90 01 04 75 06 b8 90 01 04 c3 83 f8 06 90 00 } //01 00 
		$a_01_16 = {83 f8 06 75 07 b8 04 00 00 00 eb 26 83 f8 03 75 07 } //01 00 
		$a_01_17 = {0f b7 51 06 43 83 c5 28 3b da 0f 8c } //01 00 
		$a_01_18 = {66 8b 47 06 0f b7 d8 8d 04 9b c1 e0 03 3d } //01 00 
		$a_01_19 = {8d 49 00 88 44 04 20 40 3d 00 01 00 00 7c f4 } //01 00 
		$a_01_20 = {8d 64 24 00 88 44 04 24 40 3d 00 01 00 00 7c f4 } //01 00 
		$a_01_21 = {88 10 8a 11 88 10 8a 11 40 41 4e 75 f3 } //01 00 
		$a_01_22 = {85 c0 74 08 85 c9 74 04 8a 11 88 10 40 41 4e 75 ef } //01 00 
		$a_01_23 = {85 ff 76 04 8a 11 88 10 40 41 4e 75 f3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_46{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {32 31 30 31 20 52 6f 73 65 63 72 61 6e 73 20 41 76 65 6e 75 65 2c 20 53 75 69 74 65 20 32 30 30 30 20 45 6c 20 53 65 67 75 6e 64 6f 2c 20 43 41 20 39 30 32 34 35 } //01 00 
		$a_00_1 = {61 6c 72 65 61 64 79 20 69 6e 73 74 61 6c 6c 65 64 2e 20 4e 6f 20 6e 65 65 64 20 74 6f 20 69 6e 73 74 61 6c 6c 2e 00 49 6e 74 65 72 6e 61 6c 20 65 72 72 6f 72 } //01 00 
		$a_01_2 = {74 75 72 6e 73 20 79 6f 75 72 20 62 72 6f 77 73 65 72 20 61 64 64 72 65 73 73 20 62 61 72 20 28 74 68 65 20 70 6c 61 63 65 20 77 68 65 72 65 20 79 6f 75 20 67 65 6e 65 72 61 6c 6c 79 20 74 79 70 65 20 69 6e 20 77 65 62 20 73 69 74 65 20 61 64 64 72 65 73 73 65 73 29 20 69 6e 74 6f 20 61 6e 20 49 6e 74 65 72 6e 65 74 20 73 65 61 72 63 68 20 62 6f 78 2e } //01 00 
		$a_03_3 = {74 75 72 6e 73 20 79 6f 75 72 20 62 72 6f 77 73 65 72 20 61 64 64 72 65 73 73 20 62 61 72 20 28 74 68 65 20 70 6c 61 63 65 20 77 68 65 72 65 20 79 6f 75 20 67 65 6e 65 72 61 6c 6c 79 20 69 6e 70 75 74 20 69 6e 20 77 65 62 20 73 69 74 65 90 02 02 61 64 64 72 65 73 73 65 73 29 20 69 6e 74 6f 20 61 6e 20 49 6e 74 65 72 6e 65 74 20 73 65 61 72 63 68 20 62 6f 78 2e 90 00 } //01 00 
		$a_03_4 = {6f 76 65 72 72 69 64 65 73 90 02 02 6d 6f 73 74 20 70 72 65 2d 65 78 69 73 74 69 6e 67 20 65 72 72 6f 72 20 72 65 73 6f 6c 75 74 69 6f 6e 20 61 70 70 6c 69 63 61 74 69 6f 6e 73 90 00 } //01 00 
		$a_03_5 = {46 6f 72 20 65 78 61 6d 70 6c 65 2c 20 4f 74 68 65 72 20 43 6f 6e 74 65 6e 74 20 6f 72 90 02 02 53 65 72 76 69 63 65 73 20 6d 61 79 20 69 6e 63 6c 75 64 65 20 70 61 69 64 20 73 65 61 72 63 68 20 72 65 73 75 6c 74 73 90 00 } //01 00 
		$a_03_6 = {79 6f 75 20 6d 61 79 20 62 65 20 65 78 70 6f 73 65 64 90 02 02 74 6f 20 73 75 63 68 20 4f 74 68 65 72 20 43 6f 6e 74 65 6e 74 20 6f 72 20 53 65 72 76 69 63 65 73 20 74 68 61 74 20 6d 61 79 20 62 65 20 6f 66 66 65 6e 73 69 76 65 2c 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_47{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 1a 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff ff 02 75 08 ff 55 e0 e9 } //01 00 
		$a_01_1 = {ff ff 02 75 05 ff 55 e0 eb } //01 00 
		$a_01_2 = {74 19 8b 4d fc 0f be 11 0f be 45 fb 3b d0 74 0b } //01 00 
		$a_01_3 = {74 19 8b 55 fc 0f be 02 0f be 4d fb 3b c1 74 0b } //01 00 
		$a_01_4 = {74 19 8b 45 fc 0f be 08 0f be 55 fb 3b ca 74 0b } //01 00 
		$a_03_5 = {c6 45 fb 22 8b 45 fc 83 c0 01 8b 8d 90 01 02 ff ff 89 44 8d e8 90 00 } //01 00 
		$a_03_6 = {c6 45 fb 22 8b 55 fc 83 c2 01 8b 85 90 01 02 ff ff 89 54 85 e8 90 00 } //01 00 
		$a_03_7 = {8b 4d fc 83 c1 01 8b 95 90 01 02 ff ff 89 4c 95 e8 eb 06 c6 45 fb 22 eb e8 90 00 } //01 00 
		$a_03_8 = {8b 45 fc 83 c0 01 8b 8d 90 01 02 ff ff 89 44 8d e8 eb 06 c6 45 fb 22 eb e8 90 00 } //01 00 
		$a_03_9 = {8b 55 fc 83 c2 01 8b 85 90 01 02 ff ff 89 54 85 e8 eb 06 c6 45 fb 22 eb e8 90 00 } //01 00 
		$a_03_10 = {83 f9 22 75 90 03 01 01 16 13 c6 45 fb 22 8b 45 fc 83 c0 01 90 00 } //01 00 
		$a_03_11 = {83 fa 22 75 90 03 01 01 16 13 c6 45 fb 22 8b 4d fc 83 c1 01 90 00 } //01 00 
		$a_03_12 = {83 f8 22 75 90 03 01 01 16 13 c6 45 fb 22 8b 55 fc 83 c2 01 90 00 } //01 00 
		$a_03_13 = {8b 45 fc 83 c0 01 8b 4d 90 01 01 89 44 8d 90 01 01 eb 06 c6 45 fb 22 eb eb 90 00 } //01 00 
		$a_03_14 = {8b 4d fc 83 c1 01 8b 55 90 01 01 89 4c 95 e8 eb 06 c6 45 fb 22 eb eb 90 00 } //01 00 
		$a_03_15 = {c6 45 fb 20 8b 85 90 01 02 ff ff 8b 4d fc 89 4c 85 e8 90 00 } //01 00 
		$a_03_16 = {c6 45 fb 20 8b 8d 90 01 02 ff ff 8b 55 fc 89 54 8d e8 90 00 } //01 00 
		$a_03_17 = {c6 45 fb 20 8b 95 90 01 02 ff ff 8b 45 fc 89 44 95 e8 90 00 } //01 00 
		$a_03_18 = {c6 45 fb 20 eb eb 90 09 0f 00 8b 85 90 01 02 ff ff 8b 4d fc 89 4c 85 e8 eb 06 90 00 } //01 00 
		$a_03_19 = {c6 45 fb 20 eb eb 90 09 0f 00 8b 8d 90 01 02 ff ff 8b 55 fc 89 54 8d e8 eb 06 90 00 } //01 00 
		$a_03_20 = {c6 45 fb 20 8b 4d 90 01 01 8b 55 fc 89 54 8d e8 90 00 } //01 00 
		$a_03_21 = {c6 45 fb 20 8b 45 90 01 01 8b 4d fc 89 4c 85 e8 90 00 } //01 00 
		$a_01_22 = {c6 45 fb 20 8b 55 dc 8b 45 fc 89 44 95 e8 } //01 00 
		$a_03_23 = {c6 45 fb 20 eb ee 90 09 0c 00 8b 55 90 01 01 8b 45 fc 89 44 95 e8 eb 06 90 00 } //01 00 
		$a_03_24 = {c6 45 fb 20 eb ee 90 09 0c 00 8b 45 90 01 01 8b 4d fc 89 4c 85 e8 eb 06 90 00 } //01 00 
		$a_01_25 = {eb e8 eb 17 eb 0f } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_48{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 19 00 00 01 00 "
		
	strings :
		$a_01_0 = {2c 20 80 f9 61 7c 08 80 f9 7a 7f 03 80 e9 20 3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7 } //01 00 
		$a_03_1 = {3a c1 75 15 8a 02 8a 0e 42 46 84 c0 75 d7 90 09 0f 00 04 90 03 01 01 e0 20 80 f9 90 03 01 01 61 41 7c 08 80 f9 90 03 01 01 7a 5a 7f 03 80 c1 90 03 01 01 e0 20 90 00 } //01 00 
		$a_01_2 = {8a 02 8a 0e 42 46 84 c0 74 23 84 c9 74 1f 3c 61 7c 06 3c 7a 7f 02 2c 20 } //01 00 
		$a_03_3 = {99 f7 fd 33 c0 8a 04 1a 33 d2 8a 11 03 d7 03 c2 25 ff 00 00 00 8b f8 8a 90 01 01 37 8a 90 02 03 88 90 00 } //01 00 
		$a_03_4 = {0f b6 14 02 33 c0 8a c3 03 c7 03 d0 81 e2 ff 00 00 00 8b fa 8a 04 0f 04 90 01 01 2c 90 01 01 88 1c 0f 88 04 0e 90 00 } //01 00 
		$a_01_5 = {c1 e6 03 83 ea 61 8d 0c 4e 03 d1 47 2a d0 88 55 00 8a 43 01 } //01 00 
		$a_01_6 = {83 e8 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02 8a c2 0f b6 16 2a c2 88 07 8a 46 01 } //01 00 
		$a_01_7 = {02 ca 46 eb 02 8a ca 2a c8 88 0b 8a 47 01 43 47 84 c0 } //01 00 
		$a_01_8 = {8a c2 0f b6 16 2a c2 88 07 8a 46 01 47 46 84 c0 75 05 } //01 00 
		$a_03_9 = {8b 42 04 83 e8 08 90 17 02 01 01 43 47 d1 e8 83 90 17 02 01 01 c7 c3 02 3b 90 17 02 01 01 d8 f8 72 90 00 } //01 00 
		$a_03_10 = {83 e8 08 45 d1 e8 83 c7 02 3b e8 72 90 09 03 00 8b 90 03 01 01 46 42 04 90 00 } //01 00 
		$a_01_11 = {83 c3 02 01 02 8b 46 04 83 e8 08 47 d1 e8 3b f8 72 d2 } //01 00 
		$a_01_12 = {83 c5 02 01 04 32 8b 57 04 83 ea 08 43 d1 ea 3b da 72 d6 } //01 00 
		$a_01_13 = {8b 56 04 83 ea 08 43 d1 ea 83 c7 02 3b da 72 } //01 00 
		$a_01_14 = {8b 56 04 83 ea 08 45 d1 ea 83 c7 02 3b ea 72 cb } //01 00 
		$a_01_15 = {8b 47 04 83 e8 08 45 d1 e8 83 c3 02 3b e8 72 d7 } //01 00 
		$a_01_16 = {8b 53 04 8b 44 24 10 83 ea 08 40 d1 ea 83 c5 02 3b c2 89 44 24 10 72 a6 } //01 00 
		$a_01_17 = {74 2d 2c 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02 } //01 00 
		$a_01_18 = {74 17 8a 46 01 80 e9 61 46 84 c0 74 33 2c 61 b3 1a f6 eb 02 c8 } //01 00 
		$a_01_19 = {74 31 0f be c0 83 e8 61 b3 1a f6 eb 8b 5c 24 1c 02 c2 2c 61 41 eb 02 } //01 00 
		$a_01_20 = {0f be cb 83 e9 61 8b f1 c1 e6 04 8d 0c 89 83 ea 61 8d 0c 4e } //01 00 
		$a_01_21 = {0f be c9 83 e9 61 0f be d2 83 ea 61 6b c9 1a 02 ca 46 } //01 00 
		$a_01_22 = {0f be c0 83 e8 61 b3 1a f6 eb 02 c2 2c 61 41 } //01 00 
		$a_01_23 = {f7 d8 1b c0 83 e0 70 83 c0 10 eb } //01 00 
		$a_01_24 = {80 38 2d 89 74 24 08 74 0c 8b 06 8b 48 7c 83 c0 78 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_49{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 1a 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 15 a8 72 40 00 0f be 02 85 c0 75 } //01 00 
		$a_01_1 = {8b 15 a4 72 40 00 0f be 02 85 c0 75 } //01 00 
		$a_01_2 = {8b 0d a4 72 40 00 0f be 11 85 d2 75 } //01 00 
		$a_01_3 = {8b 0d a8 72 40 00 0f be 11 85 d2 75 } //01 00 
		$a_01_4 = {72 40 00 00 75 0c c7 05 a0 72 40 00 00 00 00 00 eb } //01 00 
		$a_03_5 = {72 40 00 00 00 00 00 e9 90 01 04 c7 05 a4 72 40 00 00 00 00 00 eb 90 00 } //01 00 
		$a_03_6 = {72 40 00 00 00 00 00 eb 90 01 01 c7 05 90 03 01 01 a4 a8 72 40 00 00 00 00 00 eb 90 00 } //01 00 
		$a_03_7 = {72 40 00 00 00 00 00 eb 90 01 01 e9 90 01 04 c7 05 90 03 01 01 a0 a4 72 40 00 00 00 00 00 eb 90 00 } //01 00 
		$a_03_8 = {72 40 00 00 00 00 00 eb 90 01 01 eb 90 01 01 c7 05 a4 72 40 00 00 00 00 00 eb 90 00 } //01 00 
		$a_03_9 = {72 40 00 00 00 00 00 e9 90 01 04 c7 05 a8 72 40 00 00 00 00 00 eb e5 90 00 } //01 00 
		$a_03_10 = {c7 05 a4 72 40 00 00 00 00 00 c7 05 a0 72 40 00 00 00 00 00 eb 90 09 05 00 e9 90 00 } //01 00 
		$a_03_11 = {c7 05 a8 72 40 00 00 00 00 00 c7 05 a4 72 40 00 00 00 00 00 eb e5 90 09 05 00 e9 90 00 } //01 00 
		$a_03_12 = {c7 05 a4 72 40 00 00 00 00 00 c7 05 a0 72 40 00 00 00 00 00 eb 90 09 02 00 eb 90 00 } //01 00 
		$a_01_13 = {75 19 c7 05 a8 72 40 00 00 00 00 00 c7 05 a4 72 40 00 00 00 00 00 e9 } //01 00 
		$a_01_14 = {75 16 c7 05 a4 72 40 00 00 00 00 00 c7 05 a0 72 40 00 00 00 00 00 eb } //01 00 
		$a_01_15 = {eb 1b c7 05 a8 72 40 00 00 00 00 00 c7 05 a4 72 40 00 00 00 00 00 eb } //01 00 
		$a_03_16 = {83 f8 22 75 02 eb 90 01 01 eb 90 09 04 00 0f be 45 90 00 } //01 00 
		$a_03_17 = {83 f9 22 75 02 eb 90 01 01 eb 90 09 04 00 0f be 4d 90 00 } //01 00 
		$a_03_18 = {83 fa 22 75 02 eb 90 01 01 eb 90 09 04 00 0f be 55 90 00 } //01 00 
		$a_03_19 = {83 f8 22 75 02 eb 90 01 01 0f be 4d 90 09 04 00 0f be 45 90 00 } //01 00 
		$a_03_20 = {83 f9 22 75 02 eb 90 01 01 0f be 55 90 09 04 00 0f be 4d 90 00 } //01 00 
		$a_03_21 = {83 fa 22 75 02 eb 90 01 01 0f be 45 90 09 04 00 0f be 55 90 00 } //01 00 
		$a_03_22 = {20 7d 0b 0f be 90 01 02 83 90 01 01 09 74 02 eb 90 09 06 00 0f be 90 01 02 83 90 00 } //01 00 
		$a_03_23 = {20 7d 16 0f be 90 01 02 83 90 01 01 09 74 0d eb 90 09 06 00 0f be 90 01 02 83 90 00 } //01 00 
		$a_03_24 = {20 74 0b 0f be 90 01 02 83 90 01 01 09 74 02 eb 90 09 06 00 0f be 90 01 02 83 90 00 } //01 00 
		$a_03_25 = {20 7d 12 0f be 90 01 02 83 90 01 01 09 74 09 c6 90 09 06 00 0f be 55 fd 83 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_50{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,ffffff97 00 ffffff97 00 3c 00 00 64 00 "
		
	strings :
		$a_01_0 = {46 81 e6 ff 00 00 00 0f b6 04 0e 03 f8 81 e7 ff 00 00 00 8a 1c 0f 88 1c 0e 88 04 0f 33 db 8a 1c 0e 03 c3 8a 5d 00 25 ff 00 00 00 8a 04 08 32 c3 8b 5c 24 14 88 04 2b 45 3b ea 75 c4 } //32 00 
		$a_03_1 = {3f 70 72 6f 64 75 63 74 3d 30 26 90 02 15 76 6e 3d 30 26 90 02 15 72 65 61 3d 25 64 26 90 02 15 62 3d 90 02 15 26 90 02 15 63 69 64 3d 25 73 26 90 02 15 70 74 61 67 3d 90 02 0f 26 90 02 15 61 76 3d 25 73 26 90 02 15 61 73 3d 25 73 90 00 } //32 00 
		$a_03_2 = {3f 76 6e 3d 30 26 90 02 15 26 72 65 61 3d 25 64 26 90 02 15 63 69 64 3d 25 73 26 90 02 15 62 3d 90 02 20 70 74 61 67 3d 90 02 20 61 76 3d 25 73 26 90 02 15 70 72 6f 64 75 63 74 3d 30 26 90 02 15 61 73 3d 25 73 90 00 } //32 00 
		$a_01_3 = {53 65 63 75 72 69 74 79 43 65 6e 74 65 72 00 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 00 57 51 4c 00 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //32 00 
		$a_01_4 = {41 56 20 74 6f 6f 6c 73 3a 20 25 64 0a 00 41 53 20 74 6f 6f 6c 73 3a 20 25 64 0a 00 2d 20 6e 61 6d 65 3a 20 25 73 0a 20 20 63 6f 6d 70 61 6e 79 3a 20 25 73 0a 20 20 76 65 72 73 69 6f 6e 3a 20 25 73 0a 20 20 65 6e 61 62 6c 65 64 } //32 00 
		$a_01_5 = {6e 3d 25 73 26 63 3d 25 73 26 76 3d 25 73 26 65 3d 25 64 26 75 3d 25 64 00 26 6e 25 64 3d 25 73 26 63 25 64 3d 25 73 26 76 25 64 3d 25 73 26 65 25 64 3d 25 64 26 75 25 64 3d 25 64 } //01 00 
		$a_00_6 = {62 61 72 64 69 73 63 6f 76 65 72 } //01 00 
		$a_00_7 = {62 61 72 71 75 65 72 79 } //01 00 
		$a_00_8 = {62 61 73 69 63 73 63 61 6e } //01 00 
		$a_00_9 = {62 72 6f 77 73 65 72 64 69 73 63 6f 76 65 72 } //01 00 
		$a_00_10 = {62 72 6f 77 73 65 72 71 75 65 72 79 } //01 00 
		$a_00_11 = {62 72 6f 77 73 65 72 71 75 65 73 74 } //01 00 
		$a_00_12 = {62 72 6f 77 73 65 72 73 65 65 6b } //01 00 
		$a_00_13 = {62 72 6f 77 73 65 72 7a 69 6e 63 } //01 00 
		$a_00_14 = {66 69 6e 64 65 72 71 75 65 72 79 } //01 00 
		$a_00_15 = {66 69 6e 64 78 70 6c 6f 72 65 72 } //01 00 
		$a_00_16 = {6b 77 61 6e 7a 79 } //01 00 
		$a_00_17 = {71 75 65 72 79 62 61 72 } //01 00 
		$a_00_18 = {71 75 65 72 79 62 72 6f 77 73 65 } //01 00 
		$a_00_19 = {71 75 65 72 79 65 78 70 6c 6f 72 65 72 } //01 00 
		$a_00_20 = {71 75 65 72 79 72 65 73 75 6c 74 } //01 00 
		$a_00_21 = {71 75 65 72 79 73 63 61 6e } //01 00 
		$a_00_22 = {71 75 65 73 74 62 61 73 69 63 } //01 00 
		$a_00_23 = {71 75 65 73 74 62 61 73 69 63 6f 6e 65 } //01 00 
		$a_00_24 = {71 75 65 73 74 62 72 6f 77 73 65 } //01 00 
		$a_00_25 = {71 75 65 73 74 62 72 77 73 65 61 72 63 68 } //01 00 
		$a_00_26 = {71 75 65 73 74 64 6e } //01 00 
		$a_00_27 = {71 75 65 73 74 72 65 73 75 6c 74 } //01 00 
		$a_00_28 = {71 75 65 73 74 73 63 61 6e } //01 00 
		$a_00_29 = {71 75 65 73 74 73 63 61 6e 74 77 6f } //01 00 
		$a_00_30 = {71 75 65 73 74 73 65 72 76 69 63 65 } //01 00 
		$a_00_31 = {71 75 65 73 74 75 72 6c } //01 00 
		$a_00_32 = {72 65 73 75 6c 63 6d 64 } //01 00 
		$a_00_33 = {72 65 73 75 6c 74 62 61 72 } //01 00 
		$a_00_34 = {72 65 73 75 6c 74 62 72 6f 77 73 65 } //01 00 
		$a_00_35 = {72 65 73 75 6c 74 64 6e } //01 00 
		$a_00_36 = {72 65 73 75 6c 74 73 63 61 6e } //01 00 
		$a_00_37 = {72 65 73 75 6c 74 73 63 61 6e 6f 6e 65 } //01 00 
		$a_00_38 = {72 65 73 75 6c 74 74 6f 6f 6c } //01 00 
		$a_00_39 = {72 65 73 75 6c 74 75 72 6c } //01 00 
		$a_00_40 = {73 63 61 6e 62 61 73 69 63 } //01 00 
		$a_00_41 = {73 63 61 6e 71 75 65 72 79 } //01 00 
		$a_00_42 = {73 65 65 6b 64 6e } //01 00 
		$a_00_43 = {73 70 61 63 65 71 75 65 72 79 } //01 00 
		$a_00_44 = {74 61 62 64 69 73 63 6f 76 65 72 } //01 00 
		$a_00_45 = {74 61 62 71 75 65 72 79 } //01 00 
		$a_00_46 = {77 69 6e 6b 7a 69 6e 6b } //01 00 
		$a_00_47 = {77 79 65 6b 65 } //01 00 
		$a_00_48 = {7a 69 6e 69 6b 79 } //01 00 
		$a_00_49 = {7a 69 6e 6b 73 65 65 6b } //01 00 
		$a_00_50 = {7a 69 6e 6b 77 69 6e 6b } //01 00 
		$a_00_51 = {7a 69 6e 6b 7a 6f } //01 00 
		$a_00_52 = {7a 6f 70 74 } //01 00 
		$a_00_53 = {7a 75 6d 69 65 } //01 00 
		$a_00_54 = {7a 77 61 6e 67 69 65 } //01 00 
		$a_00_55 = {7a 77 61 6e 6b 79 73 65 61 72 63 68 } //01 00 
		$a_00_56 = {7a 77 75 6e 7a 69 } //01 00 
		$a_00_57 = {2d 70 20 51 73 74 62 73 63 } //01 00 
		$a_00_58 = {2d 70 20 42 73 63 73 63 6e } //01 00 
		$a_01_59 = {40 23 40 26 6e 55 39 50 57 45 09 5e 59 62 57 55 40 23 40 26 40 23 40 26 57 3b 09 6d 4f 6b 4b 55 } //00 00 
		$a_00_60 = {78 69 07 00 03 00 03 00 45 00 00 01 00 17 03 8b 45 fc 8b 4d 90 01 01 8b 10 33 51 04 8b 45 fc 89 10 8b 4d fc 90 00 01 00 17 03 8b 45 fc 8b 8d 90 01 04 8b 10 33 51 04 8b 45 fc 89 10 8b 4d fc 90 00 01 00 1f 03 8b 55 fc 8b 90 03 04 04 45 90 01 01 85 90 01 04 8b 0a 33 48 04 8b 55 fc 89 0a 8b 45 fc 90 00 01 00 1f 03 8b 4d fc 8b 90 03 04 04 55 90 01 01 95 90 01 04 8b 01 33 42 04 8b 4d fc 89 01 8b 55 fc 90 00 01 00 14 03 8b 4d f0 8b 55 f4 33 51 04 89 55 } //f4 eb 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_51{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 45 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8b 4d 90 01 01 8b 10 33 51 04 8b 45 fc 89 10 8b 4d fc 90 00 } //01 00 
		$a_03_1 = {8b 45 fc 8b 8d 90 01 04 8b 10 33 51 04 8b 45 fc 89 10 8b 4d fc 90 00 } //01 00 
		$a_03_2 = {8b 55 fc 8b 90 03 04 04 45 90 01 01 85 90 01 04 8b 0a 33 48 04 8b 55 fc 89 0a 8b 45 fc 90 00 } //01 00 
		$a_03_3 = {8b 4d fc 8b 90 03 04 04 55 90 01 01 95 90 01 04 8b 01 33 42 04 8b 4d fc 89 01 8b 55 fc 90 00 } //01 00 
		$a_03_4 = {8b 4d f0 8b 55 f4 33 51 04 89 55 f4 eb 90 09 02 00 eb 90 00 } //01 00 
		$a_03_5 = {8b 45 f0 8b 4d f4 33 48 04 89 4d f4 eb 90 09 02 00 eb 90 00 } //01 00 
		$a_03_6 = {8b 55 f0 8b 45 f4 33 42 04 89 45 f4 eb 90 09 02 00 eb 90 00 } //01 00 
		$a_01_7 = {8b 4d fc 8b 11 89 55 f4 8b 45 f0 8b 4d f4 33 48 04 89 4d f4 eb } //01 00 
		$a_01_8 = {8b 55 fc 8b 02 89 45 f4 8b 4d f0 8b 55 f4 33 51 04 89 55 f4 eb } //01 00 
		$a_01_9 = {8b 45 fc 8b 08 89 4d f4 8b 55 f0 8b 45 f4 33 42 04 89 45 f4 eb } //01 00 
		$a_01_10 = {8b 4d f0 8b 55 f4 33 51 04 89 55 f4 8b 45 fc 8b 4d f4 89 08 } //01 00 
		$a_01_11 = {8b 45 f0 8b 4d f4 33 48 04 89 4d f4 8b 55 fc 8b 45 f4 89 02 } //01 00 
		$a_01_12 = {8b 55 f0 8b 45 f4 33 42 04 89 45 f4 8b 4d fc 8b 55 f4 89 11 } //01 00 
		$a_01_13 = {8b 45 f4 33 45 08 89 45 f4 8b 4d fc 8b 55 f4 89 11 } //01 00 
		$a_03_14 = {8b 45 f4 33 45 08 89 45 f4 eb 90 01 01 8b 4d fc 90 01 15 8b 55 f4 89 11 90 00 } //01 00 
		$a_01_15 = {8b 4d f4 33 4d 08 89 4d f4 eb 0b 8b 55 fc 83 c2 04 89 55 fc eb 14 8b 45 fc 8b 4d f4 89 08 } //01 00 
		$a_03_16 = {83 c1 04 89 4d fc eb 90 01 01 8b 55 f4 33 55 08 89 55 f4 eb 90 01 01 eb 90 00 } //01 00 
		$a_03_17 = {8b 4d f4 33 4d 08 89 4d f4 eb 90 01 01 eb 90 01 01 eb 90 01 01 8b 55 0c 03 55 10 89 55 f8 eb 90 00 } //01 00 
		$a_03_18 = {8b 4d fc 0f be 11 83 ea 61 6b d2 1a 0f b6 85 90 01 04 03 c2 88 85 90 00 } //01 00 
		$a_03_19 = {8b 55 fc 0f be 02 83 e8 61 6b c0 1a 0f b6 8d 90 01 04 03 c8 88 8d 90 00 } //01 00 
		$a_03_20 = {8b 45 fc 0f be 08 83 e9 61 6b c9 1a 0f b6 95 90 01 04 03 d1 88 95 90 00 } //01 00 
		$a_03_21 = {8b 4d fc 0f be 11 83 ea 61 6b d2 1a 0f b6 90 01 01 e7 03 c2 88 45 90 00 } //01 00 
		$a_03_22 = {8b 55 fc 0f be 02 83 e8 61 6b c0 1a 0f b6 4d 90 01 01 03 c8 88 4d 90 00 } //01 00 
		$a_03_23 = {8b 45 fc 0f be 08 83 e9 61 6b c9 1a 0f b6 55 90 01 01 03 d1 88 55 90 00 } //01 00 
		$a_03_24 = {8b 88 24 01 00 00 8b 90 17 03 03 03 03 90 01 05 90 01 08 90 01 0b 89 84 8a 04 01 00 00 90 00 } //01 00 
		$a_03_25 = {8b 82 24 01 00 00 8b 90 17 03 03 03 03 90 01 05 90 01 08 90 01 0b 89 94 81 04 01 00 00 90 00 } //01 00 
		$a_03_26 = {8b 91 24 01 00 00 8b 90 17 03 03 03 03 90 01 05 90 01 08 90 01 0b 89 8c 90 90 04 01 00 00 90 00 } //01 00 
		$a_01_27 = {8b 55 f8 83 ea 30 89 55 f8 } //01 00 
		$a_01_28 = {8b 45 f8 83 e8 30 89 45 f8 } //01 00 
		$a_01_29 = {8b 4d f8 83 e9 30 89 4d f8 } //01 00 
		$a_00_30 = {8b 4d f4 83 e9 30 89 4d f4 } //01 00 
		$a_00_31 = {8b 4d fc 83 e9 30 89 4d fc } //01 00 
		$a_00_32 = {8b 55 fc 83 ea 30 89 55 fc } //01 00 
		$a_00_33 = {8b 45 f4 83 e8 30 89 45 f4 } //01 00 
		$a_00_34 = {8b 55 f4 83 ea 30 89 55 f4 } //01 00 
		$a_00_35 = {8b 45 fc 83 e8 30 89 45 fc } //01 00 
		$a_01_36 = {8b 45 fc 3b 45 f8 73 16 8b 4d fc 0f be 11 83 fa 22 74 0b 8b 45 fc 83 c0 01 89 45 fc eb e2 } //01 00 
		$a_01_37 = {8b 55 fc 3b 55 f8 73 16 8b 45 fc 0f be 08 83 f9 22 74 0b 8b 55 fc 83 c2 01 89 55 fc eb e2 } //01 00 
		$a_01_38 = {8b 4d fc 3b 4d f8 73 16 8b 55 fc 0f be 02 83 f8 22 74 0b 8b 4d fc 83 c1 01 89 4d fc eb e2 } //01 00 
		$a_01_39 = {8b 45 fc 0f be 08 83 f9 22 75 39 8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 89 45 f4 eb 0f } //01 00 
		$a_01_40 = {8b 4d fc 3b 4d f8 72 02 eb 18 8b 55 fc 0f be 02 83 f8 22 75 02 eb 0b 8b 4d fc 83 c1 01 89 4d fc eb de } //01 00 
		$a_01_41 = {8b 55 fc 0f be 02 83 f8 22 75 02 eb 15 8b 4d fc 3b 4d f8 72 02 eb 0b 8b 55 fc 83 c2 01 89 55 fc eb de } //01 00 
		$a_03_42 = {8b 45 fc 0f be 08 83 f9 22 75 90 01 01 eb 90 01 01 eb 90 01 01 8b 55 fc 83 c2 01 89 55 fc eb 90 00 } //01 00 
		$a_03_43 = {83 f8 22 75 90 01 01 eb 90 01 01 eb 90 01 01 8b 4d fc 83 c1 01 89 4d fc eb 90 00 } //01 00 
		$a_03_44 = {83 fa 22 75 90 01 01 eb 90 01 01 eb 90 01 01 8b 45 fc 83 c0 01 89 45 fc eb 90 00 } //01 00 
		$a_03_45 = {8b 55 fc 0f be 02 83 f8 22 75 90 01 01 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 89 55 f4 90 00 } //01 00 
		$a_03_46 = {8b 45 fc 0f be 08 83 f9 22 75 90 01 01 8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 89 45 f4 90 00 } //01 00 
		$a_03_47 = {83 f8 22 75 90 01 01 eb 90 01 01 90 03 00 04 eb 90 01 01 8b 4d fc 3b 4d f8 72 90 01 01 eb 90 01 01 8b 55 fc 83 c2 01 89 55 fc 90 00 } //01 00 
		$a_03_48 = {83 fa 22 75 90 01 01 eb 90 01 01 90 03 00 04 eb 90 01 01 8b 45 fc 3b 45 f8 72 90 01 01 eb 90 01 01 8b 4d fc 83 c1 01 89 4d fc 90 00 } //01 00 
		$a_03_49 = {83 f8 22 75 90 01 01 eb 90 01 01 eb 90 01 01 8b 4d fc 8a 11 88 55 f3 eb 90 01 01 8b 45 fc 83 c0 01 89 45 fc 90 00 } //01 00 
		$a_03_50 = {83 f9 22 75 90 01 01 eb 90 01 01 8b 55 fc 3b 55 f8 72 90 01 01 eb 90 01 01 eb 90 01 01 8b 45 fc 8a 08 88 4d f3 eb 90 00 } //01 00 
		$a_03_51 = {83 f9 22 75 90 01 01 eb 90 01 01 eb 90 01 01 90 03 00 03 90 01 14 8b 55 fc 83 c2 01 89 55 fc eb 90 01 01 eb 90 01 01 8b 45 fc 83 c0 01 90 00 } //01 00 
		$a_03_52 = {83 fa 22 75 90 01 01 8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 89 4d f4 eb 90 01 01 8b 55 fc 83 c2 01 90 00 } //01 00 
		$a_03_53 = {83 f9 22 75 90 01 01 eb 90 01 01 eb 90 01 01 8b 55 fc 8a 02 88 45 f3 eb 90 01 01 eb 90 01 01 eb 90 01 01 8b 4d fc 83 c1 01 90 00 } //01 00 
		$a_03_54 = {73 21 8b 4d 90 01 01 0f be 11 83 fa 20 74 0b 8b 45 90 01 01 0f be 08 83 f9 09 75 0b 90 00 } //01 00 
		$a_03_55 = {73 21 8b 45 90 01 01 0f be 08 83 f9 20 74 0b 8b 55 90 01 01 0f be 02 83 f8 09 75 0b 90 00 } //01 00 
		$a_03_56 = {73 21 8b 55 90 01 01 0f be 02 83 f8 20 74 0b 8b 4d 90 01 01 0f be 11 83 fa 09 75 0b 90 00 } //01 00 
		$a_01_57 = {eb 04 eb dc eb d8 eb } //01 00 
		$a_01_58 = {eb 04 eb e6 eb d8 eb } //01 00 
		$a_01_59 = {eb 04 eb e5 eb d6 eb } //01 00 
		$a_01_60 = {75 02 eb 13 eb db eb } //01 00 
		$a_01_61 = {eb 04 eb de eb d2 eb } //01 00 
		$a_01_62 = {eb e9 eb d0 eb 35 eb } //01 00 
		$a_01_63 = {eb 04 eb e7 eb d0 eb } //01 00 
		$a_01_64 = {eb 04 eb d2 eb ce eb } //01 00 
		$a_01_65 = {8b 55 08 0f be 02 83 f8 32 74 16 8b 4d 08 0f be 11 83 fa 33 74 0b 8b 45 08 0f be 08 83 f9 2e 75 } //01 00 
		$a_03_66 = {0f be 08 83 f9 32 74 16 8b 55 90 01 01 0f be 02 83 f8 33 74 0b 8b 4d 90 01 01 0f be 11 83 fa 2e 75 90 00 } //01 00 
		$a_01_67 = {8b 45 14 2b 45 0c 89 45 f8 db 45 f8 de c9 da 45 0c } //01 00 
		$a_01_68 = {8b 45 0c 2b 45 08 89 45 f8 db 45 f8 de c9 da 45 08 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Zwangi_52{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 43 72 65 61 74 65 4d 75 74 65 78 41 28 69 20 30 2c 20 69 20 30 2c 20 74 20 22 53 70 61 63 65 51 75 65 72 79 5f 49 6e 73 74 5f 6d 74 78 22 29 } //01 00 
		$a_01_1 = {3a 43 72 65 61 74 65 4d 75 74 65 78 41 28 69 20 30 2c 20 69 20 30 2c 20 74 20 22 53 70 61 63 65 51 75 65 72 79 5f 55 6e 69 6e 73 74 5f 6d 74 78 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}