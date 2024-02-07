
rule Trojan_Win32_Ursnif_MTB{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {00 6c 00 33 f6 90 0a 30 00 66 c7 05 90 01 04 6b 65 c7 05 90 01 04 32 2e 64 6c c6 05 90 01 04 72 c7 05 90 01 04 6e 65 6c 33 66 c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 ce 83 e6 03 75 0a 89 fb 66 01 da c1 ca 03 89 d7 30 10 40 c1 ca 08 e2 e7 e9 90 01 02 00 00 90 0a 4f 00 e8 00 00 00 00 5b 8d 43 90 01 01 bf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b c2 83 c0 90 01 01 8b 5c 24 90 01 01 a3 90 01 04 0f b7 ef 81 c6 90 01 04 8b c2 2b c5 89 33 83 c3 90 01 01 83 c0 90 01 01 83 6c 24 90 01 02 89 5c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_4{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 89 7d 00 0f b7 2d 90 01 04 03 c0 2b c5 83 e8 90 01 01 ff 4c 24 90 01 01 0f 85 90 01 02 ff ff 90 0a 40 00 8b 6c 24 90 01 01 83 44 24 90 01 02 8d 04 90 01 01 81 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_5{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b7 c1 2b c6 8d 58 90 01 01 2b d9 81 eb 90 01 04 0f b7 cb 81 c7 90 01 04 8b d9 03 5c 24 90 01 01 89 7d 00 8b 6c 24 10 83 c5 04 ff 4c 24 14 8d 9c 43 90 01 04 89 1d 90 01 04 89 6c 24 10 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_6{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b de 2b df 8b 7c 24 90 01 01 01 1d 90 01 04 8b 1f 0f b7 d2 8d 44 0a 90 01 01 8d 3c 90 01 01 81 f9 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {8b 44 24 14 81 c3 90 01 04 89 18 8d 84 51 90 01 04 39 15 90 01 04 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_7{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {ba 04 00 00 00 6b c2 90 0a 50 00 8b 4d 90 01 01 83 c1 90 01 01 89 4d 90 01 01 81 7d 90 01 05 0f 83 90 00 } //01 00 
		$a_02_1 = {b9 04 00 00 00 90 0a 70 00 a1 90 01 04 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 8b 15 90 01 04 89 91 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_8{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b f9 8d 81 90 01 04 8d 77 90 01 01 03 c6 89 74 24 90 01 01 66 89 35 90 01 04 a3 90 01 04 8b 74 24 90 01 01 81 c2 90 01 04 0f b7 c5 89 15 90 01 04 89 16 83 c6 04 8d 04 58 89 74 24 18 83 c0 90 01 01 ff 4c 24 90 01 01 a3 90 01 04 0f 85 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_9{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 8d 7e 90 01 01 81 c1 90 01 04 03 fa 89 0d 90 01 04 89 08 a1 90 01 04 39 05 90 01 04 76 90 00 } //01 00 
		$a_02_1 = {8b 44 24 14 83 44 24 0c 04 0f b7 c8 8d 04 95 00 00 00 00 89 4c 24 10 f7 d9 2b c8 a1 90 01 04 03 f9 ff 4c 24 18 8b 4c 24 10 0f 85 90 00 } //00 00 
		$a_00_2 = {78 } //6c 00  x
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_10{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f9 81 ff 90 01 04 8d 74 10 90 01 01 89 35 90 01 04 75 90 01 01 2b cd 2b ca 8d 4c 48 90 01 01 39 15 90 01 04 76 90 00 } //01 00 
		$a_02_1 = {0f af e8 8b 74 24 90 01 01 8b fa 2b f9 81 c7 90 01 04 8b cf 8b 3e 2b e9 81 fa 90 01 04 66 89 1d 90 01 04 75 90 00 } //01 00 
		$a_00_2 = {89 3e 8b f1 2b f0 83 c6 05 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_11{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 03 f0 8b 44 24 90 01 01 0f b7 d6 81 c7 90 01 04 89 38 39 15 90 01 04 8d 42 90 01 01 73 90 00 } //01 00 
		$a_02_1 = {5e 2b f2 69 d2 90 01 04 2b 35 90 01 04 03 c6 8b 35 90 01 04 01 15 90 01 04 89 35 90 01 04 83 44 24 90 01 02 8b d0 6b d2 90 01 01 2b 15 90 01 04 ff 4c 24 90 01 01 0f b7 f2 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_12{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f1 8d 9c 3b 90 01 04 89 1d 90 01 04 81 fe 90 01 04 75 90 02 20 a1 90 01 04 8b b4 10 90 01 04 2b dd 8b c5 83 c3 90 01 01 2b c1 66 89 1d 90 01 04 81 ff 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {2b c7 81 c6 90 01 04 89 b4 11 90 01 04 48 0f b7 db 8b c8 2b cb 83 c2 90 01 01 83 c1 90 01 01 81 fa 90 01 04 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_13{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b7 db 66 8b 7c 24 90 01 01 66 03 f8 8b 44 24 90 01 01 66 89 7c 24 90 01 01 66 89 3d 90 01 04 8b fa 2b fb 8b 00 83 ef 90 01 01 89 44 24 90 01 01 89 3d 90 01 04 81 fe 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {8b 54 24 1c 05 90 01 04 89 44 24 90 01 01 a3 90 01 04 89 02 8b d6 2b d3 81 c2 90 01 04 81 3d 90 01 08 8d 14 53 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_14{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c6 2b 05 90 01 04 0f b7 da 8d 44 07 90 01 01 8b 7d 90 01 01 a3 90 01 04 a1 90 01 04 2b c3 83 e8 90 01 01 81 f9 90 01 04 0f 85 90 00 } //01 00 
		$a_02_1 = {0f b7 c2 69 d2 90 01 04 03 15 90 01 04 8d 84 08 90 01 04 8b f0 69 f6 90 01 04 81 c7 90 01 04 89 7d 90 01 01 03 f2 83 c5 90 01 01 ff 4c 24 90 01 01 0f b7 d6 89 6c 24 90 01 01 0f 85 90 00 } //00 00 
		$a_00_2 = {78 } //7f 00  x
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_15{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b df 2b d8 83 c3 90 01 01 8b cb 2b c8 66 89 1d 90 01 04 8d 7c 0f 90 01 01 8b 44 24 90 01 01 81 c2 90 01 04 b9 90 01 04 89 10 89 15 90 01 04 66 39 0d 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {8b 54 24 10 69 c9 90 01 04 8b 12 8b c6 2b c1 0f b7 0d 90 01 04 2b 0d 90 01 04 8d 5c 29 90 01 01 8b cf 2b c8 83 c1 90 01 01 89 0d 90 01 04 81 fe 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_16{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b7 c9 8d 5f 04 03 de 89 1d 90 01 04 8d 04 11 83 f8 90 01 01 75 07 90 02 10 2b dd 2b f7 83 c3 90 01 01 83 c6 90 01 01 0f b7 ce 81 c5 90 01 04 66 89 1d 90 01 04 8b c1 8b 5c 24 10 03 e8 8b 13 81 ff 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {0f b7 f1 81 c1 90 01 04 2b f7 89 13 83 c6 90 01 01 83 c3 90 01 01 03 c6 89 5c 24 10 03 c8 ff 4c 24 14 0f 85 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_17{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 6c 24 18 0f b7 4c 24 90 01 01 0f b7 c2 8b f0 89 4c 24 90 01 01 2b 35 90 01 04 8b 6d 90 01 01 83 c6 90 01 01 66 89 0d 90 01 04 89 44 24 90 01 01 81 fb 90 01 04 0f 85 90 00 } //01 00 
		$a_02_1 = {0f b7 f1 8b 0d 90 01 04 81 c6 90 01 04 89 2d 90 01 04 2b d0 8b 44 24 18 83 44 24 18 04 0f b7 d2 89 54 24 14 89 28 a1 90 01 04 0f b7 ea 03 f5 83 6c 24 90 01 02 0f 85 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_18{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 5c 24 10 8b 2b 8b fa 2b 3d 90 01 04 8d 04 46 8d 84 08 90 01 04 83 c7 90 01 01 8d 5c 08 90 01 01 66 89 3d 90 01 04 89 1d 90 01 04 81 fe 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {8d 04 42 8d 84 08 90 01 04 8b d8 2b d9 88 15 90 01 04 03 d3 8b d8 2b de 03 cb 8b 5c 24 10 81 c5 90 01 04 89 2b 0f b6 1d 90 02 15 88 15 90 01 04 8d 14 42 03 d0 03 d1 8d 94 12 90 01 04 83 44 24 10 04 ff 4c 24 14 0f b7 c7 8d 44 08 10 90 00 } //00 00 
		$a_00_2 = {78 } //ae 00  x
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_19{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 5c 24 14 8d 04 0a 03 df 83 f8 90 01 01 75 0f 90 01 0f 8b 55 00 8d 59 90 01 01 0f af cb 81 c2 90 01 04 89 55 00 83 c5 04 89 1d 90 01 04 2b 4c 24 18 83 6c 24 10 01 75 bd 90 00 } //01 00 
		$a_02_1 = {8d 0c 03 83 f9 90 01 01 75 90 01 0a 8b 35 90 01 04 8b 6c 24 90 01 01 0f b7 cf 2b f1 81 c6 90 01 04 8b 5d 00 81 fa 90 01 04 75 90 01 0a 83 44 24 10 04 81 c3 90 01 04 0f af d0 89 5d 00 bd 90 01 02 ff ff 0f b7 cf 69 d2 90 01 04 2b ea 8b c5 2b c1 2b c2 83 6c 24 90 01 02 8b 15 90 01 04 75 92 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_20{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 18 8b 54 24 30 03 d1 89 54 24 24 8b 30 69 c5 90 01 04 89 74 24 90 01 01 8d b7 90 01 04 66 89 15 90 01 04 03 c1 8d 34 70 81 ff 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {8b 6c 24 18 8d 47 90 01 01 8b 54 24 90 01 01 03 c6 81 c2 90 01 04 0f b7 c0 89 54 24 90 01 01 89 55 00 89 15 90 01 04 8d 14 75 90 01 04 0f b7 e8 03 d5 89 44 24 90 01 01 03 d6 39 4c 24 90 01 01 76 90 00 } //01 00 
		$a_02_2 = {8b 4c 24 0c 8b 7c 24 10 83 c1 90 01 01 03 cb 0f af d8 89 4c 24 90 01 01 66 89 0d 90 01 04 8b c8 8b 3f 0f af ce 2b ca 0f b7 c9 2b d9 89 1d 90 01 04 81 fa 90 01 04 75 90 00 } //01 00 
		$a_02_3 = {8b 4c 24 0c 8b 44 24 10 81 c7 90 01 04 83 44 24 90 01 02 be 90 01 04 89 3d 90 01 04 89 38 8b 44 24 90 01 01 0f b7 f8 81 ef 90 01 04 83 6c 24 90 01 02 0f 85 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_MTB_21{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 ce 90 83 e6 03 75 0a 89 fb 66 01 da c1 ca 03 89 d7 30 10 40 90 c1 ca 08 e2 } //00 00 
	condition:
		any of ($a_*)
 
}