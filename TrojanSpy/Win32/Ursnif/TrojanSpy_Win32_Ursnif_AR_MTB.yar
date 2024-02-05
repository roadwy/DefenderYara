
rule TrojanSpy_Win32_Ursnif_AR_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 c2 8c a6 44 01 2b c8 89 15 90 01 04 2b cb 03 f1 8b 4c 24 10 89 11 8b ce 2b c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 c1 1c 4f 8d 01 03 ff 81 7c 24 1c 8d c7 00 00 89 4c 24 14 89 0d 90 01 04 89 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_3{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 20 da 0f 01 a3 90 01 04 8b 0d 90 01 04 03 4d e8 8b 15 90 01 04 89 91 7d e2 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_4{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b d1 2b 55 d8 66 89 55 b0 8b 45 b0 0f af 45 a4 0f b7 4d c4 2b c1 88 45 90 02 14 2b c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_5{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 10 03 d0 8b 44 24 14 05 20 6b 00 01 89 44 24 14 a3 90 01 04 89 07 39 15 90 01 04 77 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_6{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 0e 8b f3 6b c8 51 2b f1 8b 4c 24 0c 2b c8 81 c6 9b 54 00 00 8d 81 90 01 04 8b 4c 24 10 83 c1 04 89 4c 24 10 81 f9 90 01 04 8b 4c 24 14 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_7{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {02 4c 24 14 05 34 f7 09 01 89 06 80 e9 21 83 c6 04 83 ed 01 0f 85 } //01 00 
		$a_02_1 = {2b ef 03 e9 8b fd 8b 6c 24 10 81 c3 64 66 01 01 89 5d 00 90 02 0b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_8{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 00 50 0a 00 89 85 04 ff ff ff 8b 85 60 ff ff ff 03 45 c4 0f b7 4d cc 03 c1 66 89 85 90 01 04 8b 45 9c 03 45 ec 03 45 e4 89 45 c8 83 65 90 01 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_9{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 c7 cc f7 e5 01 03 c3 8d 94 08 67 da ff ff 89 7d 00 0f b7 0d 90 01 04 0f af c9 81 f9 d3 7a 00 00 90 00 } //01 00 
		$a_00_1 = {8b f9 2b fd 05 5c 03 0d 01 83 c7 08 ff 4c 24 18 89 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_10{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {69 c0 e8 5d 00 00 03 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 83 e9 52 2b 0d 90 01 04 03 4d 90 01 01 89 4d 90 01 01 8b 15 90 01 04 83 ea 52 2b 15 90 01 04 03 55 f4 89 55 f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_11{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 64 9f b1 01 89 01 a3 90 01 04 0f b7 05 90 01 04 8d 4b d1 3b c2 76 90 00 } //01 00 
		$a_02_1 = {83 44 24 10 04 81 c5 90 01 04 81 7c 24 10 28 1c 00 00 89 28 0f b7 c1 8d 7c 10 06 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_12{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 c1 e0 2c 70 01 89 0d 90 01 04 8b 15 90 01 04 03 55 f4 a1 90 01 04 89 82 77 df ff ff 8b 0d 90 01 04 8b 15 90 01 04 8d 84 0a 8d 7c fe ff a3 90 01 04 8b 0d 90 01 04 3b 0d 90 01 04 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_13{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {89 55 f4 89 4d fc b8 07 00 00 00 01 45 f8 8b 45 fc 8b 08 2b 4d f4 8b 55 fc 89 0a 8b e5 5d } //02 00 
		$a_02_1 = {39 55 b0 73 40 a1 90 01 03 00 89 45 80 b8 f9 cd 03 00 01 45 80 83 7d b0 00 7c 90 00 } //00 00 
		$a_00_2 = {78 50 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_14{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b c8 89 0d 90 01 04 8b 15 90 01 04 81 c2 a4 56 02 01 89 15 90 01 04 a1 90 01 04 03 45 f8 8b 0d 90 01 04 89 88 99 e7 ff ff 8b 55 fc 03 15 90 01 04 03 55 fc 89 15 90 01 04 b8 04 00 00 00 6b c8 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_15{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 10 8b ea c1 e5 05 2b ee 03 e8 8d 54 6a 1b 8b c2 2b 05 90 01 04 81 c7 ec 62 76 01 89 3b 90 00 } //01 00 
		$a_03_1 = {2b e8 19 15 90 01 04 89 2d 90 01 04 8b 44 24 14 81 c3 38 d1 9a 01 89 18 90 00 } //01 00 
		$a_01_2 = {0f b7 ef 8b c5 6b c0 2d 8d 4c 1a 43 8b 5c 24 14 8b 1b 03 c6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_16{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {83 44 24 10 04 0f b7 d0 2b d7 81 c2 2b ec 00 00 ff 4c 24 14 0f 85 } //01 00 
		$a_02_1 = {8b 54 24 10 81 c7 dc 9e 6c 01 89 3a 0f b6 15 90 01 04 89 3d 90 01 04 0f b6 3d 90 01 04 2b fa 81 ff 90 01 04 75 90 00 } //01 00 
		$a_02_2 = {89 0a 0f b6 0d 90 01 04 81 f9 c5 6e 02 00 0f b7 c0 89 44 24 10 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_17{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 de 81 c1 a4 92 51 01 0f b7 f0 89 0d 90 01 04 89 1d 90 01 04 89 0a 8b 0d 90 01 04 8b c6 83 c7 04 8d 44 08 0b a3 90 01 04 81 ff 8a 15 00 00 0f 82 90 00 } //01 00 
		$a_02_1 = {05 44 f4 01 01 89 44 24 18 89 01 b9 ff ff 00 00 a3 90 01 04 69 c3 1d 5a 00 00 2b c8 2b ce 0f af ca 90 00 } //01 00 
		$a_02_2 = {8b 44 24 10 81 c7 94 2d c9 01 89 bc 28 7f fc ff ff 8a 15 90 01 04 0f b6 ea bb 59 00 00 00 81 fd cc 18 00 00 75 90 00 } //01 00 
		$a_00_3 = {81 c6 24 a9 91 01 8d 84 10 f9 82 fe ff 89 b4 39 64 da ff ff 8d 4c 00 04 8b e9 2b eb 83 c7 04 8d 44 28 c9 81 ff 6c 26 00 00 0f } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_18{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 4d f0 83 c1 01 89 4d f0 8b 55 f4 81 c2 74 80 00 00 0f b6 45 eb 2b d0 88 55 eb } //01 00 
		$a_02_1 = {81 c1 94 ce 08 01 89 0d 90 01 04 8b 15 90 01 04 03 55 f0 a1 90 01 04 89 82 50 eb ff ff 8b 4d f4 83 e9 46 90 00 } //01 00 
		$a_02_2 = {8b 54 24 10 05 cc 31 06 01 89 02 66 8b 35 90 01 04 a3 90 01 04 bb 48 5f 01 00 b8 c9 1a 00 00 2b d9 90 00 } //01 00 
		$a_02_3 = {8b 7c 24 10 8d 44 0e fd 81 c2 a8 c0 03 01 0f b7 c0 89 17 0f b7 f8 89 15 90 01 04 8d 74 3e 05 90 00 } //01 00 
		$a_02_4 = {81 c3 88 ea 42 01 89 9c 2e ce ef ff ff 8b 3d 90 01 04 0f b7 f2 8d 90 01 01 46 7e 00 00 8d 04 56 03 c2 39 3d 90 00 } //01 00 
		$a_02_5 = {8b 54 24 10 05 c4 d1 01 01 89 02 81 3d 90 01 04 67 07 00 00 a3 90 01 04 0f b6 c3 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_19{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {73 00 68 00 65 00 6c 00 6c 00 2e 00 52 00 75 00 6e 00 28 00 22 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 46 00 20 00 2f 00 54 00 4e 00 20 00 5c 00 22 00 90 02 14 5c 00 22 00 20 00 2f 00 54 00 52 00 20 00 5c 00 22 00 22 00 20 00 2b 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 2b 00 20 00 22 00 5c 00 22 00 20 00 2f 00 53 00 43 00 20 00 4d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 4d 00 4f 00 20 00 90 10 02 00 22 00 29 00 3b 00 90 00 } //02 00 
		$a_02_1 = {73 68 65 6c 6c 2e 52 75 6e 28 22 73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 43 72 65 61 74 65 20 2f 46 20 2f 54 4e 20 5c 22 90 02 14 5c 22 20 2f 54 52 20 5c 22 22 20 2b 20 63 6f 6d 6d 61 6e 64 20 2b 20 22 5c 22 20 2f 53 43 20 4d 69 6e 75 74 65 20 2f 4d 4f 20 90 10 02 00 22 29 3b 90 00 } //02 00 
		$a_02_2 = {58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 27 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 27 00 29 00 3b 00 20 00 65 00 76 00 61 00 6c 00 28 00 90 12 09 00 2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 27 00 48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 5c 00 5c 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 5c 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 43 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 65 00 72 00 5c 00 5c 00 5c 00 5c 00 41 00 70 00 70 00 73 00 77 00 36 00 34 00 5c 00 5c 00 5c 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 55 00 72 00 6c 00 90 00 } //02 00 
		$a_02_3 = {58 4f 62 6a 65 63 74 28 27 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 3b 20 65 76 61 6c 28 90 12 09 00 2e 52 65 67 52 65 61 64 28 27 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 5c 5c 5c 53 6f 66 74 77 61 72 65 5c 5c 5c 5c 41 70 70 6c 69 63 61 74 69 6f 6e 43 6f 6e 74 61 69 6e 65 72 5c 5c 5c 5c 41 70 70 73 77 36 34 5c 5c 5c 5c 53 65 72 76 65 72 55 72 6c 90 00 } //00 00 
		$a_00_4 = {7e 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_20{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 75 70 b8 3b 2d 0b 00 01 45 70 8b 45 7c 8b 55 70 8a 14 02 88 14 01 5e } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_AR_MTB_21{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 94 06 3b 2d 0b 00 88 14 01 5e 8b e5 5d } //01 00 
		$a_01_1 = {b8 bb df 9f 03 f7 a5 a8 fe ff ff 8b 85 a8 fe ff ff b8 ed 2b b0 26 f7 a5 28 ff ff ff 8b 85 28 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}