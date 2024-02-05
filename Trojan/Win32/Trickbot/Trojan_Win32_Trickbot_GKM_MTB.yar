
rule Trojan_Win32_Trickbot_GKM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 8b 4d 90 01 01 8b 55 90 01 01 03 c1 8a 14 32 30 10 41 3b 4d 90 01 01 89 4d 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 18 f6 d0 88 45 90 01 01 3b d9 73 90 01 01 eb 90 01 01 8a 45 90 01 01 8a cb 2a 4d 90 01 01 32 0b 32 c8 88 0b 03 df 85 f6 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 33 c9 f7 35 90 01 04 33 c0 8b 44 24 90 01 01 8a 0c 38 8a 14 32 32 ca 88 0c 38 8b 4c 24 90 01 01 40 3b c1 89 44 24 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c8 0f b6 04 37 89 55 90 01 01 0f b6 d3 03 c2 33 d2 f7 35 90 01 04 8a 04 32 30 01 ff 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 8b 08 8b 55 90 01 01 8b 02 8b 55 90 01 01 8b 75 90 01 01 8a 0c 0a 32 0c 06 8b 55 90 01 01 8b 02 8b 55 90 01 01 88 0c 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_6{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 55 0c 8a 0c 32 f6 d1 8b c6 3b f7 73 90 01 01 8a d0 2a d3 32 10 32 d1 88 10 03 45 90 01 01 3b c7 72 90 01 01 46 ff 4d 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_7{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 08 8b 55 90 01 01 8b 02 8b 55 90 01 01 0f b6 04 02 8b 55 90 01 01 0f b6 0c 0a 33 c8 8b 55 90 01 01 8b 02 8b 55 90 01 01 88 0c 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_8{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 0c 32 f6 d1 8b c6 3b f7 73 90 01 01 8a d0 2a d3 32 10 32 d1 88 10 03 45 90 01 01 3b c7 72 90 01 01 8b 55 90 01 01 46 ff 4d 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_9{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e 90 01 01 8b 4c 24 90 01 01 8d 4c 19 90 01 01 8a 11 88 90 01 05 40 49 3b c3 7c 90 01 01 8d 43 01 c6 83 90 01 04 00 83 f8 3e 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_10{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b fa 8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 f7 35 90 01 04 8b 44 24 90 01 01 8a 14 0a 30 54 28 90 01 01 3b 6c 24 1c 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_11{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d2 0f b6 04 37 03 c1 f7 35 90 01 04 8b da ff 15 90 01 04 8b 45 90 01 01 8b 4d 90 01 01 8a 14 33 03 c1 30 10 41 3b 4d 90 01 01 89 4d 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_12{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 0c 02 f6 d1 3b c6 73 90 01 01 8a d0 2a 55 90 01 01 32 10 32 d1 88 10 03 c7 3b c6 72 90 01 01 8b 45 90 01 01 40 ff 4d 90 01 01 89 45 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_13{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 0a f6 d0 88 45 90 01 01 8b d9 3b 4d 90 01 01 73 90 01 01 eb 90 01 01 8a 45 90 01 01 8a cb 2a 4d 90 01 01 be 23 00 00 00 32 0b 32 c8 88 0b 6a 14 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_14{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 0c 32 f6 d1 8b c6 3b f7 73 90 01 01 eb 90 01 01 8d 49 00 8a d0 2a d3 32 10 32 d1 88 10 03 45 90 01 01 3b c7 72 90 01 01 8b 55 90 01 01 46 ff 4d 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_15{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {99 b9 14 02 00 00 f7 f9 8a 5d 00 8b 44 24 90 01 01 83 c0 f0 c7 84 24 90 01 04 ff ff ff ff 8d 48 90 01 01 8a 54 14 18 32 da 88 5d 00 45 83 ca ff f0 0f c1 11 4a 85 d2 7f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_16{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d2 f7 35 90 01 04 89 55 90 01 01 8b 45 90 01 01 8b 08 8b 55 90 01 01 8b 02 8b 55 90 01 01 8b 75 90 01 01 8a 0c 0a 32 0c 06 8b 55 90 01 01 8b 02 8b 55 90 01 01 88 0c 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_17{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 2f 88 04 3b 88 0c 2f 0f b6 04 3b 0f b6 c9 03 c1 33 d2 f7 35 90 01 04 89 54 24 90 00 } //01 00 
		$a_02_1 = {8a 14 3a 30 14 08 8b 4c 24 90 01 01 40 3b c1 89 44 24 90 01 01 0f 82 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_18{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f bf fa 3b bd 90 01 04 7f 90 01 01 8b 41 90 01 01 8b 51 90 01 01 2b c2 33 d2 8a 14 38 03 c7 89 85 90 01 04 8b 45 90 01 01 8a 14 02 8b 85 90 01 04 88 10 8b 85 90 01 04 03 f8 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_19{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 c1 40 f7 d9 8a 4c 0a 90 01 01 88 88 90 01 04 eb 90 01 01 c6 83 90 01 04 00 43 83 fb 3d 7f 90 01 01 c6 83 90 01 04 01 eb 90 00 } //01 00 
		$a_00_1 = {71 62 77 43 2b 3c 46 24 7a 40 49 76 33 70 5f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_20{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 8a 04 37 81 e1 ff 00 00 00 03 c1 f7 35 90 01 04 89 54 24 90 01 01 ff 15 90 01 04 8b 54 24 90 01 01 8b 44 24 90 01 01 8a 0c 32 8a 14 28 32 d1 88 14 28 8b 44 24 90 01 01 45 3b e8 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_21{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 f7 35 90 01 04 8b ea ff 15 90 01 04 85 c0 74 90 01 01 ff 15 90 01 04 8a 14 2e 8b 44 24 90 01 01 8b 6c 24 90 01 01 8a 0c 28 32 ca 88 0c 28 8b 4c 24 90 01 01 40 3b c1 89 44 24 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_22{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b fa 8b 54 24 90 01 01 81 e2 ff 00 00 00 8a 04 0f 88 04 0e 33 c0 88 1c 0f 8a 04 0e 03 c2 33 d2 f7 35 90 01 04 8b 44 24 90 01 01 8a 1c 28 8a 14 0a 32 da 88 1c 28 8b 44 24 90 01 01 45 3b e8 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_23{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e 90 01 01 8b 4c 24 90 01 01 8d 4c 19 90 01 01 8a 11 88 90 01 05 40 49 3b c3 7c 90 01 01 8d 43 90 01 01 c6 83 90 01 04 00 83 f8 3e 7d 90 00 } //01 00 
		$a_00_1 = {31 43 24 49 79 71 7a 48 2a 51 4d 39 76 48 4c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_24{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e 90 01 01 8b 4c 24 90 01 01 8d 4c 19 90 01 01 8a 11 88 90 01 05 40 49 3b c3 7c 90 01 01 8d 43 90 01 01 c6 83 90 01 04 00 83 f8 3e 7d 90 00 } //01 00 
		$a_00_1 = {52 43 72 42 4b 63 6f 21 23 62 6f 44 4c 30 44 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_25{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 11 99 f7 fb 8d 45 90 01 01 50 8b da ff 15 90 01 04 8a 0c 30 32 d9 8d 4d 90 01 01 51 ff 15 90 01 04 8d 4d 90 01 01 88 1c 30 ff 15 90 01 04 8b 4d 90 01 01 8b 1d 90 01 04 b8 01 00 00 00 03 c8 89 4d 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_26{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d2 f7 f1 8b 45 90 01 01 89 55 90 01 01 8d 0c 1a 8a 14 1a 88 14 18 8a 55 90 01 01 88 11 0f b6 04 18 0f b6 ca 03 c1 33 d2 f7 35 90 01 04 89 55 90 00 } //01 00 
		$a_02_1 = {03 c1 8a 14 1a 30 10 41 3b 4d 90 01 01 89 4d 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_27{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f0 81 fb 00 01 00 00 72 90 01 01 ff 15 90 01 04 8b 0f 8b 51 90 01 01 8b 4d 90 01 01 8a 04 32 8b 75 90 01 01 88 04 19 b8 01 00 00 00 03 c3 0f 80 90 01 04 8b d8 eb 90 01 01 8b 17 52 6a 01 ff 15 90 01 04 66 83 c6 02 89 85 90 01 04 0f 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_28{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 33 f6 d0 8b ce 3b f7 73 90 01 01 eb 90 01 01 8d 49 00 8a d9 2a da 32 19 32 d8 88 19 03 4d 90 01 01 3b cf 72 90 01 01 8b 5d 90 01 01 46 ff 4d 90 01 01 75 90 00 } //01 00 
		$a_00_1 = {45 46 6f 71 65 6b 6b 6b 42 43 65 67 41 72 62 67 72 6d 47 72 6d 67 74 47 47 6d 6b 61 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_29{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b cb 8b f0 c7 04 24 90 01 04 e8 90 01 04 8b cb 89 45 90 01 01 c7 04 24 90 01 04 e8 90 01 04 59 33 db 53 6a 01 53 89 45 90 01 01 53 8d 45 90 01 01 50 89 5d 90 01 01 ff d6 85 c0 75 90 00 } //01 00 
		$a_00_1 = {45 53 45 54 20 68 79 75 6e 79 61 } //01 00 
		$a_00_2 = {48 24 49 3c 4a 52 45 4a 2b 77 31 23 4d 2b 48 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_30{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 11 99 f7 fb 8d 45 90 01 01 50 8b da ff 15 90 01 04 8b 4e 90 01 01 8b 56 90 01 01 2b ca 8a 14 08 32 da 8d 55 90 01 01 52 ff 15 90 01 04 8b 4e 90 01 01 8b 56 90 01 01 2b ca 88 1c 08 8d 4d 90 01 01 ff 15 90 01 04 8b 4d 90 01 01 8b 1d 90 01 04 b8 01 00 00 00 03 c8 8b 45 90 01 01 89 4d 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_31{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8d 45 90 01 01 89 5d 90 01 01 50 53 ff 75 90 01 01 6a 4c 68 90 01 04 ff 75 90 01 01 e8 90 01 04 85 c0 5f 74 90 01 01 8b 45 90 01 01 ff 30 50 ff 75 90 01 01 53 6a 01 53 ff 75 90 01 01 e8 90 01 04 85 c0 0f 95 c0 eb 90 00 } //01 00 
		$a_00_1 = {69 39 6a 32 31 3f 74 47 4f 56 29 52 77 41 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_32{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f0 81 fb 00 01 00 00 72 90 01 01 ff 15 90 01 04 8b 07 8b 48 90 01 01 8b 45 90 01 01 8a 14 31 8b 75 90 01 01 88 14 18 b8 01 00 00 00 03 c3 0f 80 90 01 04 8b d8 eb 90 00 } //01 00 
		$a_02_1 = {0f bf c9 3b 4d 90 01 01 7f 90 01 01 8b 16 8b 42 90 01 01 8b 7a 90 01 01 2b c7 33 d2 8a 14 08 8d 3c 08 8b 45 90 01 01 8a 14 02 8b 45 90 01 01 88 17 03 c8 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_33{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 01 8a 14 37 88 04 37 88 11 49 47 3b 7d 08 7e } //01 00 
		$a_02_1 = {85 c0 59 75 90 01 01 8b 45 90 01 01 0f b7 00 8b 3c 83 03 7d 90 01 01 ff 45 90 01 01 83 45 90 01 01 04 8b 45 90 01 01 83 45 90 01 01 02 3b 46 90 01 01 72 90 00 } //01 00 
		$a_00_2 = {53 74 75 70 69 64 20 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 } //01 00 
		$a_00_3 = {61 6d 75 4e 78 45 63 6f 6c 6c 41 6c 61 75 74 72 69 56 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_GKM_MTB_34{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {8a 04 33 f6 d0 8b ce 3b f7 73 90 01 01 eb 90 01 01 8d 49 00 8a d9 2a da 32 19 32 d8 88 19 03 4d 90 01 01 3b cf 72 90 01 01 8b 5d 90 01 01 46 ff 4d 90 01 01 75 90 00 } //01 00 
		$a_00_1 = {51 4d 53 56 4d 49 46 54 4f 49 54 41 4d 41 49 54 45 51 4a 42 4b 51 4e 47 53 50 48 56 56 51 43 4a 53 4b 47 4d 53 44 46 46 4a 48 4f 56 4a } //01 00 
		$a_00_2 = {4c 47 51 51 57 59 50 4a 42 54 47 45 53 46 51 54 58 55 4a 4b 4f 58 49 5a 59 44 49 56 44 4e 41 55 43 45 43 4f 4d 56 } //01 00 
		$a_00_3 = {66 61 71 78 73 7a 75 72 62 76 79 66 77 6f 63 77 6e 79 72 76 6c 73 62 70 75 68 78 62 68 74 66 61 63 79 61 7a 6e 72 70 74 73 6a 62 } //00 00 
	condition:
		any of ($a_*)
 
}