
rule Trojan_Win32_Trickbot_RM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 fb 8b 75 90 01 01 8b c1 8a 1c 31 80 c2 4f 32 da 47 88 1c 31 b9 05 00 00 00 99 f7 f9 89 7d 90 01 01 85 d2 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 e8 8d 44 6d 90 01 01 2b d0 a1 90 01 04 8b d8 0f af d8 8b c1 03 c2 8a 14 03 8b 44 24 90 01 01 8a 18 32 da 8b 54 24 90 01 01 88 18 8b 44 24 90 01 01 40 3b c2 89 44 24 90 01 01 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 8a 1c 02 a1 90 01 04 0f af 05 90 01 04 2b d8 03 90 01 05 8b 90 01 02 8a 04 0a 32 c3 8b 90 01 02 8b 11 8b 90 01 02 88 04 11 e9 90 00 } //1
		$a_81_1 = {44 48 4b 57 25 61 29 54 45 50 77 78 25 4b 78 61 76 21 51 78 72 59 41 77 74 53 42 51 6a 6e 4e 53 40 3f 68 4a 46 49 4e 4c 50 62 62 76 6d 37 43 4e 21 } //1 DHKW%a)TEPwx%Kxav!QxrYAwtSBQjnNS@?hJFINLPbbvm7CN!
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_RM_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {ff 30 50 ff 75 90 01 01 53 6a 01 53 ff 75 90 01 01 ff 55 90 01 01 85 c0 0f 95 c0 eb 90 01 01 32 c0 90 00 } //1
		$a_02_1 = {59 33 c0 bf e0 73 48 00 39 75 90 01 01 f3 ab aa 89 1d 90 01 04 0f 86 90 01 04 80 7d 90 01 01 00 0f 84 90 01 04 8d 4d 90 01 01 8a 11 84 d2 0f 84 90 00 } //1
		$a_01_2 = {36 49 68 4e 39 47 44 72 23 61 4b 2b 61 73 4b } //1 6IhN9GDr#aK+asK
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Trickbot_RM_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 45 e8 c7 45 90 01 01 42 00 00 00 e8 90 01 04 8b 4d 90 01 01 85 c9 76 90 01 01 8b 45 90 01 01 8d a4 24 90 01 04 8a 10 80 f2 63 80 c2 63 88 10 83 c0 01 83 e9 01 75 90 00 } //10
		$a_81_1 = {42 5a 59 54 59 2e 70 6e 67 } //5 BZYTY.png
		$a_81_2 = {4f 4c 45 41 43 43 2e 64 6c 6c } //1 OLEACC.dll
		$a_81_3 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //1 GetSystemInfo
		$a_81_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=18
 
}
rule Trojan_Win32_Trickbot_RM_MTB_6{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 35 90 01 04 a0 90 01 04 8a 14 0a 02 d0 8b 44 24 90 01 01 8a 1c 28 32 da 88 1c 28 8b 44 24 90 01 01 45 3b e8 72 90 00 } //1
		$a_81_1 = {78 34 4e 4c 73 67 78 53 23 2a 4a 77 47 39 5f 5f 68 54 49 21 6b 6f 52 71 63 36 37 65 4c 64 37 64 29 68 48 4f 72 58 6c 48 4c 38 54 58 2b 79 71 3e 32 4f 79 77 39 35 69 46 4d 43 79 49 3e 55 79 2b 4c 70 72 5a 28 21 6c 69 29 49 73 2b 4b 52 50 77 49 5a 7a 7a 5f 33 44 75 6e 3f 66 34 5a 55 71 5f 3f 56 } //1 x4NLsgxS#*JwG9__hTI!koRqc67eLd7d)hHOrXlHL8TX+yq>2Oyw95iFMCyI>Uy+LprZ(!li)Is+KRPwIZzz_3Dun?f4ZUq_?V
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_RM_MTB_7{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {44 24 20 53 68 65 6c 51 50 } //1 D$ ShelQP
		$a_81_1 = {44 24 2c 6c 45 78 65 } //1 D$,lExe
		$a_81_2 = {44 24 30 63 75 74 65 } //1 D$0cute
		$a_81_3 = {47 65 74 50 72 6f 63 65 73 73 56 65 72 73 69 6f 6e } //1 GetProcessVersion
		$a_81_4 = {47 65 74 43 50 49 6e 66 6f } //1 GetCPInfo
		$a_81_5 = {47 65 74 53 79 73 74 65 6d 4d 65 74 72 69 63 73 } //1 GetSystemMetrics
		$a_81_6 = {41 66 78 4f 6c 64 57 6e 64 50 72 6f 63 34 32 33 } //1 AfxOldWndProc423
		$a_81_7 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_81_8 = {47 65 74 4b 65 79 53 74 61 74 65 } //1 GetKeyState
		$a_81_9 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}