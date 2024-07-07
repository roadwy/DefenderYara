
rule Trojan_Win32_Qakbot_GP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 4b 8b 45 d8 33 18 89 5d a0 90 02 32 03 d8 8b 45 d8 89 18 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GP_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 04 e4 ff ff 0f 00 59 51 33 0c 90 02 01 33 8b 90 02 04 83 e0 00 31 c8 59 68 90 02 04 8f 83 90 02 04 21 8b 90 02 04 89 4d 90 02 01 8b 8b 90 02 04 01 c1 51 8b 4d 90 02 01 58 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GP_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 04 e4 ff ff 0f 00 59 89 4d 90 02 01 33 4d 90 02 01 0b 8b 90 02 04 83 e0 00 09 c8 8b 4d 90 02 01 54 c7 04 e4 90 02 04 8f 83 90 02 04 21 8b 90 02 04 6a 00 89 3c 90 02 01 50 5f 03 bb 90 02 04 89 f8 5f ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GP_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c8 89 4d 90 01 01 0f b6 15 90 01 04 8b 45 90 01 01 2b c2 89 45 90 01 01 0f b6 0d 90 01 04 8b 55 90 01 01 2b d1 89 55 90 01 01 0f b6 05 90 01 04 33 45 90 01 01 89 45 90 01 01 8b 0d 90 01 04 03 4d 90 01 01 8a 55 90 01 01 88 11 e9 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GP_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {31 d2 31 c2 89 93 90 01 04 8b 55 90 01 01 ff 93 90 01 04 83 bb 90 01 04 00 90 00 } //10
		$a_02_1 = {59 fc 83 bb 90 01 04 00 90 18 f3 a4 83 bb 90 01 04 00 75 90 01 01 ff 93 90 01 04 6a 00 89 34 e4 29 f6 31 c6 89 b3 90 01 04 5e 57 c7 04 e4 ff ff 0f 00 59 83 bb 90 01 04 00 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Qakbot_GP_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {b8 4c 66 44 00 cc cc ff 15 90 01 04 68 dc 0f 07 10 c3 90 00 } //5
		$a_00_1 = {c0 c0 07 68 09 28 07 10 c3 } //5
		$a_00_2 = {32 c1 68 4b 0f 07 10 c3 } //5
		$a_00_3 = {68 ea 0e 00 00 68 a7 e7 06 10 68 a7 e7 06 10 b8 8c fa 06 10 ff d0 } //5
		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GP_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec a1 90 02 04 a3 90 02 04 8b 90 02 06 89 90 02 06 8b 90 02 06 8b 02 a3 90 02 04 8b 90 02 06 81 90 02 06 89 90 02 06 8b 90 02 06 81 90 02 06 a1 90 02 04 a3 90 02 04 31 0d 90 02 04 a1 90 02 04 c7 05 90 02 08 01 90 02 05 8b 15 90 02 04 a1 90 02 04 89 02 5d c3 90 00 } //1
		$a_02_1 = {88 0a 8b 55 90 01 01 83 c2 90 01 01 89 55 90 01 01 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GP_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 05 00 00 "
		
	strings :
		$a_02_0 = {ff 75 fc ff 75 f8 ff 75 f0 ff 75 f4 ff 35 90 01 04 6a 01 ff 90 0a 30 00 8b 90 01 02 03 90 01 02 89 90 01 02 83 90 01 02 04 81 90 01 02 00 10 00 00 90 00 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_00_2 = {99 03 04 24 13 54 24 04 83 c4 08 } //3
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*3+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=19
 
}
rule Trojan_Win32_Qakbot_GP_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_80_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
		$a_80_1 = {62 31 39 36 62 32 38 37 2d 62 61 62 34 2d 31 30 31 61 2d 62 36 39 63 2d 30 30 61 61 30 30 33 34 31 64 30 37 } //b196b287-bab4-101a-b69c-00aa00341d07  1
		$a_80_2 = {52 65 67 4f 70 65 6e 4b 65 79 41 } //RegOpenKeyA  1
		$a_02_3 = {8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 33 c0 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 90 02 c8 a1 90 01 04 c7 05 90 01 04 00 00 00 00 01 05 90 00 } //10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_02_3  & 1)*10) >=12
 
}
rule Trojan_Win32_Qakbot_GP_MTB_10{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 01 ff 25 90 0a 48 00 a1 90 01 04 03 05 90 01 04 a3 90 01 04 83 05 90 01 03 00 04 81 2d 90 01 03 00 00 10 00 00 ff 35 90 01 03 00 ff 35 90 01 03 00 ff 35 90 01 03 00 ff 35 90 01 03 00 ff 35 90 01 03 00 90 00 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GP_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 0a c8 00 03 d8 a1 90 01 04 01 18 90 02 05 8b 1d 90 01 04 03 1d 90 01 04 03 1d 90 01 04 4b 2b d8 90 02 05 03 d8 a1 90 01 04 90 17 02 01 01 31 33 90 00 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GP_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_02_0 = {57 c7 45 ec 0e dc eb d2 3a d2 74 00 81 6d ec c4 00 00 00 e8 90 01 04 66 3b c9 74 90 00 } //10
		$a_00_1 = {ff 75 0c ff 75 08 eb 00 ff 55 f8 } //1
		$a_00_2 = {ff 75 b0 ff 55 f0 3a d2 74 } //1
		$a_80_3 = {34 66 33 66 39 62 30 35 30 30 65 63 61 65 30 38 30 30 30 30 30 30 30 30 38 30 34 38 38 62 63 34 34 38 38 39 35 38 30 38 34 63 38 39 34 38 } //4f3f9b0500ecae080000000080488bc4488958084c8948  1
		$a_00_4 = {c6 45 ba 53 80 45 ba 19 66 3b f6 74 } //1
		$a_00_5 = {c6 45 be 59 80 45 be 10 3a c9 74 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=15
 
}
rule Trojan_Win32_Qakbot_GP_MTB_13{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {2b d8 01 5d 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 0a c8 00 8b d8 8b 45 90 01 01 03 45 90 01 01 2d 67 2b 00 00 03 45 90 01 01 03 d8 90 02 4b 90 17 02 01 01 31 33 90 00 } //10
		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //5
		$a_02_2 = {8b 55 e0 03 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 4d 90 01 01 e8 90 00 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}
rule Trojan_Win32_Qakbot_GP_MTB_14{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
		$a_80_1 = {62 31 39 36 62 32 38 37 2d 62 61 62 34 2d 31 30 31 61 2d 62 36 39 63 2d 30 30 61 61 30 30 33 34 31 64 30 37 } //b196b287-bab4-101a-b69c-00aa00341d07  1
		$a_80_2 = {52 65 67 4f 70 65 6e 4b 65 79 41 } //RegOpenKeyA  1
		$a_02_3 = {03 f0 8b 45 90 01 01 03 30 8b 4d 90 01 01 89 31 8b 55 90 01 01 8b 02 2d bc 01 00 00 8b 4d 90 01 01 89 01 5e 8b e5 5d c3 90 00 } //1
		$a_02_4 = {8a 0c 32 88 0c 38 8b 55 90 01 01 83 c2 90 01 01 89 55 90 01 01 eb 90 01 01 5f 5e 8b e5 5d c3 90 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Qakbot_GP_MTB_15{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } //1 DrawThemeIcon
		$a_01_1 = {5a 67 66 53 53 77 75 44 76 41 55 71 4a 47 64 4c 62 4f 58 52 53 43 70 42 45 57 63 72 56 57 45 76 48 4c 2e 64 6c 6c } //1 ZgfSSwuDvAUqJGdLbOXRSCpBEWcrVWEvHL.dll
		$a_01_2 = {6c 47 56 75 45 75 5a 6d 4b 65 59 69 47 63 71 71 6b 41 2e 64 6c 6c } //1 lGVuEuZmKeYiGcqqkA.dll
		$a_01_3 = {73 6d 6d 61 69 61 2e 64 6c 6c } //1 smmaia.dll
		$a_01_4 = {50 7a 4f 56 75 6d 54 71 53 73 64 41 6a 41 72 5a 63 71 6e 2e 64 6c 6c } //1 PzOVumTqSsdAjArZcqn.dll
		$a_01_5 = {59 69 78 63 50 4e 74 6a 74 65 54 49 74 78 77 79 4d 72 54 55 79 54 62 47 46 52 46 66 48 63 65 4c 52 4e 77 2e 64 6c 6c } //1 YixcPNtjteTItxwyMrTUyTbGFRFfHceLRNw.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}