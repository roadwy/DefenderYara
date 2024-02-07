
rule Trojan_Win32_Trickbot_KMG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c6 99 f7 f9 0f b6 04 2b 8b f2 8a 14 2e 88 14 2b 88 04 2e 0f b6 0c 2e 0f b6 04 2b 03 c1 99 b9 90 01 04 f7 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c0 ec 02 80 e4 0f 0a e1 8b 4c 24 90 01 01 88 64 24 90 01 01 88 44 24 90 01 01 88 47 90 01 01 0f b7 44 24 90 01 01 66 89 07 83 44 24 08 03 8b 44 24 90 01 01 40 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e 90 01 01 8b 4c 24 90 01 01 8d 4c 19 90 01 01 8a 11 88 90 01 05 40 49 3b c3 7c 90 01 01 8d 43 01 c6 83 90 01 04 00 83 f8 3e 7d 90 00 } //01 00 
		$a_00_1 = {38 42 68 66 31 41 51 41 62 38 38 4d 40 72 77 } //00 00  8Bhf1AQAb88M@rw
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e 90 01 01 8b 4c 24 90 01 01 8d 4c 19 90 01 01 8a 11 88 90 01 05 40 49 3b c3 7c 90 01 01 8d 43 01 c6 83 90 01 04 00 83 f8 3e 7d 90 00 } //01 00 
		$a_00_1 = {6f 64 71 40 29 64 35 56 30 66 25 52 31 26 50 } //00 00  odq@)d5V0f%R1&P
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e 90 01 01 8b 4c 24 90 01 01 8d 4c 19 90 01 01 8a 11 88 90 01 05 40 49 3b c3 7c 90 01 01 8d 43 01 c6 83 90 01 04 00 83 f8 3e 7d 90 00 } //01 00 
		$a_00_1 = {7a 31 3e 67 3e 61 55 66 51 2b 37 68 63 39 3e } //00 00  z1>g>aUfQ+7hc9>
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_6{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 c7 45 8c 00 01 00 00 c7 45 90 01 01 02 00 00 00 ff 15 90 01 04 8b d0 8d 4d 90 01 01 ff 15 90 01 04 8d 4d 90 01 01 51 ff 15 90 01 04 8b 56 90 01 01 8b 4e 90 01 01 2b d1 88 04 1a 8b 85 90 01 04 03 d8 e9 90 01 04 68 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_7{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 f6 3b fb 7e 90 01 01 8d 87 90 01 04 8a 08 88 8e 90 01 04 46 48 3b f7 7c 90 01 01 8d 47 90 01 01 83 f8 3e 88 9f 90 01 04 7d 90 00 } //01 00 
		$a_00_1 = {45 53 45 54 20 68 79 75 6e 79 61 } //01 00  ESET hyunya
		$a_00_2 = {62 29 58 21 51 4d 42 4a 49 5f 78 54 41 76 4a } //00 00  b)X!QMBJI_xTAvJ
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_KMG_MTB_8{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 3b fb 7e 90 01 01 8b 54 24 90 01 01 8d 4c 3a 90 01 01 8b ff 8a 11 88 90 01 05 40 49 3b c7 7c 90 01 01 8d 47 01 83 f8 3e 88 9f 90 01 04 7d 90 00 } //01 00 
		$a_00_1 = {23 6f 71 34 34 64 32 3f 45 31 41 56 31 30 6b } //01 00  #oq44d2?E1AV10k
		$a_00_2 = {53 74 75 70 20 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 68 61 68 61 68 } //00 00  Stup windows defender hahah
	condition:
		any of ($a_*)
 
}