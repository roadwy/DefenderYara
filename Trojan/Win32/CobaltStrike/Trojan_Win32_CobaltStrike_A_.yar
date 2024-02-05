
rule Trojan_Win32_CobaltStrike_A_{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81 c3 90 01 04 ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0 90 00 } //01 00 
		$a_03_1 = {6a 40 68 00 30 00 00 57 6a 00 ff 75 08 ff 15 90 01 04 8b f0 85 f6 74 90 01 01 8d 45 fc 50 57 ff 75 f8 56 ff 75 08 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__2{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 90 01 04 ff d3 41 b8 90 01 04 68 04 00 00 00 5a 48 89 f9 ff d0 00 00 00 00 00 00 00 00 90 00 } //01 00 
		$a_01_1 = {41 b9 00 30 00 00 4d 8b c7 33 d2 48 8b cf c7 44 24 20 40 00 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__3{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {fc 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a } //01 00 
		$a_01_1 = {e9 4f ff ff ff 5d 6a 00 49 be 77 69 6e 69 6e 65 74 00 41 56 49 89 e6 4c 89 f1 41 ba 4c 77 26 07 ff d5 48 31 c9 48 31 d2 4d 31 c0 4d 31 c9 41 50 41 50 41 ba 3a 56 79 a7 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__4{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff e0 58 5f 5a 8b 12 eb 86 5b 80 7e 10 00 75 3b c6 46 10 01 68 a6 95 bd 9d ff d3 3c 06 7c 1a } //01 00 
		$a_01_1 = {31 c9 51 51 ff 76 08 ff 36 51 51 68 38 68 0d 16 ff d3 c9 } //01 00 
		$a_01_2 = {e8 00 00 00 00 58 83 c0 25 83 ec 08 89 e2 c7 42 04 33 00 00 00 89 02 e8 09 00 00 00 } //01 00 
		$a_01_3 = {48 31 d2 48 8b 0e 41 ba c8 38 a4 40 ff d5 48 85 c0 74 0c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__5{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 b9 00 10 00 00 4c 8d 87 80 00 00 00 48 89 d6 c7 44 24 20 04 00 00 00 31 d2 ff 15 90 01 04 48 89 c5 48 8d 44 24 50 4d 89 e0 49 89 f9 48 89 ea 48 89 d9 48 89 44 24 20 ff 15 90 00 } //01 00 
		$a_01_1 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 } //01 00 
		$a_01_2 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__6{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 4a 0d ce 09 e8 } //01 00 
		$a_01_1 = {68 d0 03 5c 09 e8 } //01 00 
		$a_01_2 = {68 f4 15 93 b0 e8 } //01 00 
		$a_01_3 = {68 31 74 bc 7f e8 } //01 00 
		$a_01_4 = {68 b0 06 6a 90 e8 } //01 00 
		$a_01_5 = {68 9c b8 ba a6 57 e8 } //01 00 
		$a_01_6 = {68 78 5c 3b 55 e8 } //01 00 
		$a_01_7 = {68 65 41 fb a7 e8 } //01 00 
		$a_01_8 = {6a 40 68 00 30 00 00 8b 46 50 50 8b 46 34 50 ff d7 } //01 00 
		$a_03_9 = {25 61 70 70 64 61 74 61 25 5c 46 6c 61 73 68 50 6c 61 79 65 72 00 90 02 08 5c 70 6c 75 67 31 2e 64 61 74 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__7{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 b8 00 30 00 00 31 c9 48 89 f7 ff 15 90 01 04 48 89 c3 31 c0 39 f8 7d 16 48 89 c2 83 e2 03 41 8a 14 14 32 54 05 00 88 14 03 48 ff c0 eb e6 90 00 } //01 00 
		$a_01_1 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 } //01 00 
		$a_03_2 = {b9 60 ea 00 00 ff d3 eb f7 90 02 10 48 ff e1 90 00 } //01 00 
		$a_01_3 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__8{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 b9 04 00 00 00 48 63 f2 49 89 cc 89 d7 4c 89 c5 48 89 f2 41 b8 00 30 00 00 31 c9 ff 15 } //01 00 
		$a_03_1 = {41 b8 20 00 00 00 ff 15 90 01 04 4c 8d 90 01 04 90 01 01 49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 90 00 } //01 00 
		$a_01_2 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 } //01 00 
		$a_01_3 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__9{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 01 6a 02 e8 90 02 30 6a 02 58 ff 75 08 66 89 45 ec e8 90 02 40 6a 78 56 ff 15 90 00 } //01 00 
		$a_03_1 = {8e 4e 0e ec 74 90 01 01 81 7d 90 01 01 aa fc 0d 7c 74 90 01 01 81 7d 90 01 01 54 ca af 91 74 90 00 } //01 00 
		$a_01_2 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00 } //01 00 
		$a_01_3 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55 } //01 00 
		$a_01_4 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__10{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 5d 08 c7 44 24 10 04 00 00 00 c7 44 24 0c 00 10 00 00 8d 87 80 00 00 00 89 44 24 08 c7 44 24 04 00 00 00 00 89 1c 24 ff 15 90 01 04 83 ec 14 89 c6 8d 45 e0 89 44 24 10 8b 45 1c 89 7c 24 0c 89 74 24 04 89 1c 24 89 44 24 08 ff 15 90 01 04 8b 45 e0 83 ec 14 39 f8 75 90 00 } //01 00 
		$a_01_1 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00 } //01 00 
		$a_01_2 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__11{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 f9 8e 4e 0e ec 74 90 01 01 81 f9 aa fc 0d 7c 74 90 01 01 81 f9 54 ca af 91 74 90 00 } //01 00 
		$a_01_1 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16 } //01 00 
		$a_01_2 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5 } //01 00 
		$a_01_3 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd } //01 00 
		$a_01_4 = {48 b8 73 79 73 74 65 6d 33 32 48 83 cb ff 48 89 07 4c 8b c3 49 ff c0 42 80 7c 07 09 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__12{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 5a e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81 c3 90 01 02 00 00 ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0 90 00 } //01 00 
		$a_03_1 = {8e 4e 0e ec 74 90 01 01 81 7d 90 01 01 aa fc 0d 7c 74 90 01 01 81 7d 90 01 01 54 ca af 91 74 90 00 } //01 00 
		$a_01_2 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00 83 65 c0 00 } //01 00 
		$a_01_3 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55 } //01 00 
		$a_01_4 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__13{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 75 0c c7 44 24 0c 04 00 00 00 c7 44 24 08 00 30 00 00 c7 04 24 00 00 00 00 89 74 24 04 ff 15 } //01 00 
		$a_03_1 = {c7 44 24 08 20 00 00 00 ff 15 90 01 04 83 ec 10 89 5c 24 0c c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 08 90 01 04 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff 15 90 00 } //01 00 
		$a_01_2 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00 } //01 00 
		$a_01_3 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__14{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 ff e1 41 54 55 57 56 53 48 83 ec 40 41 b9 04 00 00 00 48 63 f2 48 89 cd 90 02 15 41 b8 00 30 00 00 90 00 } //01 00 
		$a_03_1 = {4c 8d 4c 24 3c 48 89 f2 48 89 d9 41 b8 20 00 00 00 ff 15 90 01 04 4c 8d 90 01 02 ff ff ff 49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 90 01 04 90 90 48 83 c4 40 90 00 } //01 00 
		$a_01_2 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 } //01 00 
		$a_01_3 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__15{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 58 83 c0 25 83 ec 08 89 e2 c7 42 04 33 00 00 00 89 02 e8 09 00 00 00 } //01 00 
		$a_01_1 = {f0 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a } //01 00 
		$a_01_2 = {48 31 d2 48 8b 0e 41 ba c8 38 a4 40 ff d5 48 85 c0 74 0c } //9c ff 
		$a_01_3 = {4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 64 00 65 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 68 00 65 00 6c 00 70 00 65 00 72 00 00 00 } //9c ff 
		$a_01_4 = {4f 00 75 00 74 00 62 00 79 00 74 00 65 00 20 00 50 00 43 00 20 00 52 00 65 00 70 00 61 00 69 00 72 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__16{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8b 45 08 5d ff e0 55 89 e5 90 02 20 c7 44 24 0c 04 00 00 00 c7 44 24 08 00 30 00 00 c7 04 24 00 00 00 00 90 00 } //01 00 
		$a_03_1 = {c7 44 24 08 20 00 00 00 89 44 24 0c ff 15 90 01 04 83 ec 10 89 90 01 01 24 0c c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 08 90 01 04 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff 15 90 00 } //01 00 
		$a_01_2 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00 } //01 00 
		$a_01_3 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__17{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 6f 75 6c 64 20 6e 6f 74 20 72 75 6e 20 63 6f 6d 6d 61 6e 64 20 28 77 2f 20 74 6f 6b 65 6e 29 20 62 65 63 61 75 73 65 20 6f 66 20 69 74 73 20 6c 65 6e 67 74 68 20 6f 66 20 25 64 20 62 79 74 65 73 21 } //01 00 
		$a_81_1 = {63 6f 75 6c 64 20 6e 6f 74 20 73 70 61 77 6e 20 25 73 20 28 74 6f 6b 65 6e 29 3a 20 25 64 } //01 00 
		$a_81_2 = {49 27 6d 20 61 6c 72 65 61 64 79 20 69 6e 20 53 4d 42 20 6d 6f 64 65 } //01 00 
		$a_81_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 22 25 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__18{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 90 01 04 ff d3 41 b8 f0 b5 a2 56 68 04 00 00 00 5a 48 89 f9 ff d0 90 00 } //01 00 
		$a_03_1 = {81 f9 8e 4e 0e ec 74 90 01 01 81 f9 aa fc 0d 7c 74 90 01 01 81 f9 54 ca af 91 74 90 00 } //01 00 
		$a_01_2 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16 } //01 00 
		$a_01_3 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5 } //01 00 
		$a_01_4 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__19{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,2a 00 2a 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {81 f9 5b bc 4a 6a 74 } //0a 00 
		$a_03_1 = {8e 4e 0e ec 74 90 01 01 81 90 01 01 aa fc 0d 7c 74 90 01 01 81 90 01 01 54 ca af 91 90 00 } //0a 00 
		$a_03_2 = {3c 33 c9 41 b8 00 30 00 00 4c 03 90 01 01 44 8d 49 40 41 8b 90 00 } //0a 00 
		$a_01_3 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //01 00 
		$a_01_4 = {5c 5c 2e 5c 70 69 70 65 5c 73 73 68 61 67 65 6e 74 } //01 00 
		$a_01_5 = {63 6f 6e 6e 65 63 74 20 74 6f 20 25 73 3a 25 64 20 66 61 69 6c 65 64 3a 20 25 73 00 } //01 00 
		$a_00_6 = {43 4f 42 41 4c 54 53 54 52 49 4b 45 } //01 00 
		$a_01_7 = {25 31 30 32 34 5b 5e 20 5d 20 25 38 5b 5e 3a 5d 3a 2f 2f 25 31 30 31 36 5b 5e 2f 5d 25 37 31 36 38 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__20{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,2a 00 2a 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {75 b1 81 7d 90 01 01 5b bc 4a 6a 75 0b 90 00 } //0a 00 
		$a_03_1 = {8e 4e 0e ec 74 90 01 01 81 7d 90 01 01 aa fc 0d 7c 74 90 01 01 81 7d 90 01 01 54 ca af 91 90 00 } //0a 00 
		$a_03_2 = {6a 40 68 00 30 00 00 8b 90 01 02 8b 90 01 03 6a 00 ff 55 90 00 } //0a 00 
		$a_01_3 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //01 00 
		$a_01_4 = {5c 5c 2e 5c 70 69 70 65 5c 73 73 68 61 67 65 6e 74 } //01 00 
		$a_01_5 = {63 6f 6e 6e 65 63 74 20 74 6f 20 25 73 3a 25 64 20 66 61 69 6c 65 64 3a 20 25 73 00 } //01 00 
		$a_00_6 = {43 4f 42 41 4c 54 53 54 52 49 4b 45 } //01 00 
		$a_01_7 = {25 31 30 32 34 5b 5e 20 5d 20 25 38 5b 5e 3a 5d 3a 2f 2f 25 31 30 31 36 5b 5e 2f 5d 25 37 31 36 38 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__21{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e 4e 0e ec 74 90 01 01 81 7d 90 01 01 aa fc 0d 7c 74 90 01 01 81 7d 90 01 01 54 ca af 91 74 90 00 } //01 00 
		$a_01_1 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00 83 65 c0 00 } //01 00 
		$a_01_2 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55 } //01 00 
		$a_01_3 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da } //01 00 
		$a_03_4 = {83 c4 10 33 c0 80 b0 90 01 04 69 40 3d 00 10 00 00 7c f1 68 00 10 00 00 b9 90 01 04 8d 44 24 14 e8 90 00 } //01 00 
		$a_03_5 = {62 65 61 63 6f 6e 90 02 04 2e 64 6c 6c 00 90 00 } //01 00 
		$a_01_6 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__22{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 f9 8e 4e 0e ec 74 90 01 01 81 f9 aa fc 0d 7c 74 90 01 01 81 f9 54 ca af 91 74 90 00 } //01 00 
		$a_01_1 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16 } //01 00 
		$a_01_2 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5 } //01 00 
		$a_01_3 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd } //01 00 
		$a_01_4 = {41 8b c7 80 34 28 69 48 ff c0 48 3d 00 10 00 00 7c f1 48 8d 4c 24 20 41 b8 00 10 00 00 48 8b d5 e8 } //01 00 
		$a_03_5 = {62 65 61 63 6f 6e 90 02 04 2e 64 6c 6c 00 90 00 } //01 00 
		$a_01_6 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__23{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {fc e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 } //01 00 
		$a_01_1 = {eb 86 5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 31 ff 57 57 57 57 57 68 3a 56 79 a7 ff d5 } //01 00 
		$a_03_2 = {eb 86 5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 90 02 08 50 68 ea 0f df e0 ff d5 90 00 } //01 00 
		$a_01_3 = {eb 86 5d 31 c0 6a 40 b4 10 68 00 10 00 00 68 ff ff 07 00 6a 00 68 58 a4 53 e5 ff d5 83 c0 40 89 c7 50 31 c0 b0 70 b4 69 50 68 64 6e 73 61 54 68 4c 77 26 07 ff d5 } //01 00 
		$a_01_4 = {68 58 a4 53 e5 ff d5 50 e9 a8 00 00 00 5a 31 c9 51 51 68 00 b0 04 00 68 00 b0 04 00 6a 01 6a 06 6a 03 52 68 45 70 df d4 ff d5 50 8b 14 24 6a 00 52 68 28 6f 7d e2 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__24{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,3e 00 3e 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {81 f9 8e 4e 0e ec 74 90 01 01 81 f9 aa fc 0d 7c 74 90 01 01 81 f9 54 ca af 91 74 90 00 } //0a 00 
		$a_01_1 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16 } //0a 00 
		$a_01_2 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5 } //0a 00 
		$a_01_3 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd } //0a 00 
		$a_01_4 = {41 8b c7 80 34 28 69 48 ff c0 48 3d 00 10 00 00 7c f1 48 8d 4c 24 20 41 b8 00 10 00 00 48 8b d5 e8 } //0a 00 
		$a_01_5 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //01 00 
		$a_01_6 = {57 6f 77 36 34 44 69 73 61 62 6c 65 57 6f 77 36 34 46 73 52 65 64 69 72 65 63 74 69 6f 6e 00 } //01 00 
		$a_01_7 = {53 74 61 72 74 65 64 20 73 65 72 76 69 63 65 20 25 73 20 6f 6e 20 25 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__25{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,34 00 34 00 1b 00 00 0a 00 "
		
	strings :
		$a_03_0 = {5b bc 4a 6a 0f 85 90 01 01 00 00 00 8b 90 00 } //0a 00 
		$a_03_1 = {8e 4e 0e ec 74 90 02 03 aa fc 0d 7c 74 90 02 03 54 ca af 91 75 90 00 } //0a 00 
		$a_01_2 = {b8 0a 4c 53 75 } //0a 00 
		$a_03_3 = {68 00 30 00 00 90 0a 0a 00 6a 40 90 0a 10 00 8b 90 01 01 3c 90 00 } //0a 00 
		$a_01_4 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //01 00 
		$a_01_5 = {5c 5c 2e 5c 70 69 70 65 5c 62 79 70 61 73 73 75 61 63 } //01 00 
		$a_01_6 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6c 00 69 00 63 00 6f 00 6e 00 66 00 67 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_7 = {5b 2d 5d 20 49 43 6f 72 52 75 6e 74 69 6d 65 48 6f 73 74 3a 3a 47 65 74 44 65 66 61 75 6c 74 44 6f 6d 61 69 6e } //01 00 
		$a_01_8 = {5b 2d 5d 20 49 6e 76 6f 6b 65 5f 33 20 } //01 00 
		$a_01_9 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 72 00 75 00 6e 00 61 00 73 00 00 00 } //01 00 
		$a_01_10 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 } //01 00 
		$a_01_11 = {5c 5c 2e 5c 70 69 70 65 5c 6b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_01_12 = {5b 75 6e 6b 6e 6f 77 6e 3a 20 25 30 32 58 5d } //01 00 
		$a_01_13 = {2f 73 65 6e 64 25 73 00 50 4f 53 54 } //01 00 
		$a_01_14 = {72 63 61 70 3a 2f 2f 00 45 72 72 6f 72 } //01 00 
		$a_01_15 = {5c 5c 2e 5c 70 69 70 65 5c 6e 65 74 76 69 65 77 } //01 00 
		$a_01_16 = {20 25 2d 32 32 73 20 25 2d 32 30 73 20 25 2d 31 34 73 20 25 73 } //01 00 
		$a_01_17 = {5c 5c 2e 5c 70 69 70 65 5c 70 6f 77 65 72 73 68 65 6c 6c } //01 00 
		$a_01_18 = {49 43 4c 52 52 75 6e 74 69 6d 65 49 6e 66 6f 3a 3a 49 73 4c 6f 61 64 61 62 6c 65 } //01 00 
		$a_01_19 = {5c 5c 2e 5c 70 69 70 65 5c 73 63 72 65 65 6e 73 68 6f 74 } //01 00 
		$a_01_20 = {00 4a 50 45 47 4d 45 4d 00 } //01 00 
		$a_01_21 = {5c 5c 2e 5c 70 69 70 65 5c 65 6c 65 76 61 74 65 } //01 00 
		$a_01_22 = {5b 2a 5d 20 25 73 20 6c 6f 61 64 65 64 20 69 6e 20 75 73 65 72 73 70 61 63 65 } //01 00 
		$a_01_23 = {5c 5c 2e 5c 70 69 70 65 5c 68 61 73 68 64 75 6d 70 } //01 00 
		$a_01_24 = {47 6c 6f 62 61 6c 5c 53 41 4d } //01 00 
		$a_01_25 = {5c 5c 2e 5c 70 69 70 65 5c 70 6f 72 74 73 63 61 6e } //01 00 
		$a_01_26 = {5c 5c 25 73 5c 69 70 63 24 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_A__26{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,34 00 34 00 1d 00 00 0a 00 "
		
	strings :
		$a_03_0 = {81 f9 5b bc 4a 6a 0f 85 90 01 01 00 00 00 49 90 00 } //0a 00 
		$a_03_1 = {81 f9 8e 4e 0e ec 74 90 01 01 81 f9 aa fc 0d 7c 74 90 01 01 81 f9 54 ca af 91 90 00 } //0a 00 
		$a_01_2 = {b8 0a 4c 53 75 } //0a 00 
		$a_01_3 = {48 63 5f 3c 33 c9 41 b8 00 30 00 00 48 03 df 44 8d 49 40 8b 53 50 41 ff d6 } //0a 00 
		$a_01_4 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //01 00 
		$a_01_5 = {5c 5c 2e 5c 70 69 70 65 5c 62 79 70 61 73 73 75 61 63 } //01 00 
		$a_01_6 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6c 00 69 00 63 00 6f 00 6e 00 66 00 67 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_7 = {5b 2d 5d 20 49 43 6f 72 52 75 6e 74 69 6d 65 48 6f 73 74 3a 3a 47 65 74 44 65 66 61 75 6c 74 44 6f 6d 61 69 6e } //01 00 
		$a_01_8 = {5b 2d 5d 20 49 6e 76 6f 6b 65 5f 33 20 } //01 00 
		$a_01_9 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 72 00 75 00 6e 00 61 00 73 00 00 00 } //01 00 
		$a_01_10 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 } //01 00 
		$a_01_11 = {5c 5c 2e 5c 70 69 70 65 5c 6b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_01_12 = {5b 75 6e 6b 6e 6f 77 6e 3a 20 25 30 32 58 5d } //01 00 
		$a_01_13 = {2f 73 65 6e 64 25 73 00 50 4f 53 54 } //01 00 
		$a_01_14 = {72 63 61 70 3a 2f 2f 00 45 72 72 6f 72 } //01 00 
		$a_01_15 = {5c 5c 2e 5c 70 69 70 65 5c 6e 65 74 76 69 65 77 } //01 00 
		$a_01_16 = {20 25 2d 32 32 73 20 25 2d 32 30 73 20 25 2d 31 34 73 20 25 73 } //01 00 
		$a_01_17 = {5c 5c 2e 5c 70 69 70 65 5c 70 6f 77 65 72 73 68 65 6c 6c } //01 00 
		$a_01_18 = {49 43 4c 52 52 75 6e 74 69 6d 65 49 6e 66 6f 3a 3a 49 73 4c 6f 61 64 61 62 6c 65 } //01 00 
		$a_01_19 = {5c 5c 2e 5c 70 69 70 65 5c 73 63 72 65 65 6e 73 68 6f 74 } //01 00 
		$a_01_20 = {00 4a 50 45 47 4d 45 4d 00 } //01 00 
		$a_01_21 = {5c 5c 2e 5c 70 69 70 65 5c 6d 69 6d 69 6b 61 74 7a } //01 00 
		$a_01_22 = {74 6f 6b 65 6e 3a 3a 65 6c 65 76 61 74 65 } //01 00 
		$a_01_23 = {5c 5c 2e 5c 70 69 70 65 5c 68 61 73 68 64 75 6d 70 } //01 00 
		$a_01_24 = {47 6c 6f 62 61 6c 5c 53 41 4d } //01 00 
		$a_01_25 = {5c 5c 2e 5c 70 69 70 65 5c 65 6c 65 76 61 74 65 } //01 00 
		$a_01_26 = {5b 2a 5d 20 25 73 20 6c 6f 61 64 65 64 20 69 6e 20 75 73 65 72 73 70 61 63 65 } //01 00 
		$a_01_27 = {5c 5c 2e 5c 70 69 70 65 5c 70 6f 72 74 73 63 61 6e } //01 00 
		$a_01_28 = {5c 5c 25 73 5c 69 70 63 24 00 } //00 00 
	condition:
		any of ($a_*)
 
}