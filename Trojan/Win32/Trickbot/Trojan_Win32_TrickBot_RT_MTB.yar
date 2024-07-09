
rule Trojan_Win32_TrickBot_RT_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 80 c2 64 85 f6 76 ?? 8b 45 ?? 8a 08 32 ca 02 ca 88 08 40 4e 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBot_RT_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b eb 7e ?? 8b 54 24 ?? 8d 4c 2a ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c5 7c ?? 8d 45 ?? 83 f8 3e 88 9d ?? ?? ?? ?? 7d } //1
		$a_01_1 = {3f 6f 47 62 21 64 6f 24 50 62 23 2b 69 51 4a } //1 ?oGb!do$Pb#+iQJ
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_TrickBot_RT_MTB_3{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 04 0e 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 8b 5d ec 2b df } //1
		$a_80_1 = {77 68 6f 61 6d 69 2e 65 78 65 } //whoami.exe  2
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*2) >=3
 
}
rule Trojan_Win32_TrickBot_RT_MTB_4{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 04 37 81 e1 ff 00 00 00 03 c1 f7 35 ?? ?? ?? ?? 8b ea ff 15 ?? ?? ?? ?? 85 c0 74 ?? ff 15 ?? ?? ?? ?? 8a 14 2e 8b 44 24 ?? 8b 6c 24 ?? 8a 0c 28 32 ca 88 0c 28 8b 4c 24 ?? 40 3b c1 89 44 24 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBot_RT_MTB_5{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8d 45 ?? 89 5d ?? 50 53 ff 75 ?? 6a 4c 68 b8 51 47 00 ff 75 ?? ff 55 ?? 85 c0 74 ?? 8b 45 ?? ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? ff 55 ?? 85 c0 0f 95 c0 eb ?? 32 c0 } //1
		$a_01_1 = {70 4d 32 77 74 30 62 34 31 34 21 6e 66 72 61 } //1 pM2wt0b414!nfra
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_TrickBot_RT_MTB_6{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c2 2b 05 ?? ?? ?? ?? 8b 55 ?? 8b 75 ?? 8a 0c 0a 32 0c 06 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 75 } //1
		$a_81_1 = {51 67 3c 47 32 4f 6c 71 2b 25 78 61 48 79 53 6d 7a 57 6f 68 45 48 6b 65 29 42 2a 43 32 36 41 69 4b 28 50 4c 2a 62 38 33 30 36 43 40 3c 6f 30 38 50 31 72 30 7a 50 6a 50 } //1 Qg<G2Olq+%xaHySmzWohEHke)B*C26AiK(PL*b8306C@<o08P1r0zPjP
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_Win32_TrickBot_RT_MTB_7{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c3 03 f2 25 ff 00 00 00 33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 44 24 ?? 88 1c 2e 8b 3d ?? ?? ?? ?? 40 41 3b c7 89 44 24 ?? 72 } //1
		$a_81_1 = {28 33 28 61 6e 39 31 58 70 37 70 4e 26 51 47 3c 66 4b 43 5e 48 74 42 26 74 73 69 37 72 4c 35 29 62 74 74 70 57 6a 44 6c 73 32 38 4a 64 59 28 4a 4e 76 45 69 53 61 57 62 72 51 55 5a 6b 54 38 4a 79 41 3c 48 62 46 5a 78 28 6a 4e 4b 4e 43 } //1 (3(an91Xp7pN&QG<fKC^HtB&tsi7rL5)bttpWjDls28JdY(JNvEiSaWbrQUZkT8JyA<HbFZx(jNKNC
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_Win32_TrickBot_RT_MTB_8{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c1 f7 35 ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? 8b ?? ?? 8d 0c 02 8a c3 f6 eb 8b ?? ?? 8a 1c 33 2a d8 30 19 42 3b ?? ?? 89 ?? ?? 72 } //1
		$a_81_1 = {5f 4b 45 72 47 5a 30 32 40 3f 55 56 4a 45 52 3e 37 2b 48 50 58 68 6e 4b 4e 32 6d 51 65 24 75 23 6e 62 76 63 30 33 4c 59 59 51 3e 57 29 73 5f 24 5e 71 28 4a 29 39 57 59 35 4c 4a 36 42 5a 76 3f 59 4b 6d 36 67 66 2a 7a 71 72 33 6b 68 43 5f 4d 29 74 24 69 38 78 49 40 78 23 6c 76 67 56 4a 5e 6d 55 47 73 32 51 35 72 52 29 68 59 65 46 } //1 _KErGZ02@?UVJER>7+HPXhnKN2mQe$u#nbvc03LYYQ>W)s_$^q(J)9WY5LJ6BZv?YKm6gf*zqr3khC_M)t$i8xI@x#lvgVJ^mUGs2Q5rR)hYeF
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_Win32_TrickBot_RT_MTB_9{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {41 66 78 4f 6c 64 57 6e 64 50 72 6f 63 34 32 33 } //1 AfxOldWndProc423
		$a_81_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 78 78 78 2e 63 6f 6d 2f 31 2e 6a 70 67 } //1 http://www.xxx.com/1.jpg
		$a_81_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_81_3 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_5 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
		$a_81_6 = {50 6f 73 74 4d 65 73 73 61 67 65 41 } //1 PostMessageA
		$a_81_7 = {47 65 74 53 79 73 74 65 6d 4d 65 74 72 69 63 73 } //1 GetSystemMetrics
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Trojan_Win32_TrickBot_RT_MTB_10{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c1 01 89 4d ?? 8b 55 ?? 3b 15 ?? ?? ?? ?? 73 ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 8b 45 ?? 33 d2 f7 75 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 8a 14 11 88 10 eb } //1
		$a_01_1 = {4f 3e 79 31 2a 56 74 3c 5f 79 58 50 2a 44 54 44 77 37 40 2a 32 3f 30 43 6d 2b 43 47 3e 40 36 6e 56 4d 6f 30 54 75 48 37 40 24 68 30 5a 21 46 74 3e 6f 69 47 47 47 51 74 28 2a 35 41 68 78 2a 71 } //1 O>y1*Vt<_yXP*DTDw7@*2?0Cm+CG>@6nVMo0TuH7@$h0Z!Ft>oiGGGQt(*5Ahx*q
		$a_01_2 = {6e 68 57 58 29 72 4e 4c 6d 62 2a 37 23 50 39 2a 74 74 73 51 3f 23 6c 5a 53 64 4c 6d 38 34 39 4a 23 57 44 4c 35 49 53 57 70 73 70 35 31 54 3f 4b 68 34 31 58 56 6d 77 49 37 3c 36 72 4a 67 67 5f 28 5a 35 72 6b 44 48 45 49 5f 71 3c 64 5f 71 61 63 67 57 4b 4d 21 6f 52 3e } //1 nhWX)rNLmb*7#P9*ttsQ?#lZSdLm849J#WDL5ISWpsp51T?Kh41XVmwI7<6rJgg_(Z5rkDHEI_q<d_qacgWKM!oR>
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}