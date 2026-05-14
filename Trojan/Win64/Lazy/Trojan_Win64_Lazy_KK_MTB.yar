
rule Trojan_Win64_Lazy_KK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 85 ec 00 00 00 48 8d 15 ?? ?? 00 00 0f b6 04 10 83 f0 ?? 89 c1 8b 85 ec 00 00 00 48 8d 15 ?? ?? 00 00 88 0c 10 83 85 ec 00 00 00 01 } //30
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 48 } //5 C:\WindoH
		$a_01_2 = {77 73 5c 53 79 73 74 65 48 } //4 ws\SysteH
		$a_01_3 = {6d 33 32 5c 52 75 6e 74 48 } //3 m32\RuntH
		$a_01_4 = {69 6d 65 42 72 6f 6b 65 48 } //2 imeBrokeH
		$a_01_5 = {6b 65 72 2e 65 78 65 } //1 ker.exe
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*5+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=45
 
}
rule Trojan_Win64_Lazy_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {42 0f be 14 07 49 ff c0 69 cb ?? ?? ?? ?? 2b d1 81 e2 ?? ?? ?? ?? 03 da 4c 3b c0 } //20
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 64 72 61 67 6f 6e 77 65 6c 6c 5c 4a 61 76 61 5c 6a 61 76 61 70 61 74 68 } //10 C:\ProgramData\dragonwell\Java\javapath
		$a_00_2 = {66 6f 72 20 2f 66 20 22 74 6f 6b 65 6e 73 3d 32 20 64 65 6c 69 6d 73 3d 3a 20 22 20 25 69 20 69 6e 20 28 27 73 63 20 71 75 65 72 79 65 78 20 53 63 68 65 64 75 6c 65 20 5e 7c 20 66 69 6e 64 73 74 72 20 50 49 44 27 29 20 64 6f 20 74 61 73 6b 6b 69 6c 6c 20 2f 50 49 44 20 25 69 20 2f 46 } //5 for /f "tokens=2 delims=: " %i in ('sc queryex Schedule ^| findstr PID') do taskkill /PID %i /F
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_00_2  & 1)*5) >=35
 
}
rule Trojan_Win64_Lazy_KK_MTB_3{
	meta:
		description = "Trojan:Win64/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {4c 8b dc 48 83 ec 48 33 c0 c7 44 24 38 ?? ?? 00 00 89 44 24 50 4d 8d 4b 10 49 89 43 10 4d 8d 43 18 49 89 43 18 49 8d 53 20 49 89 43 20 49 8d 4b e8 48 8d 05 ?? ?? ff ff 48 05 ?? ?? 00 00 48 89 44 24 30 49 8d 43 08 0f 28 44 24 30 66 0f 7f 44 24 30 49 89 43 d8 e8 ?? ?? 00 00 48 83 c4 48 } //5
		$a_01_1 = {47 0f b6 04 13 41 c1 e0 18 41 33 c0 8d 0c 00 8b d1 81 f2 b7 1d c1 04 85 c0 0f 49 d1 8d 04 12 8b c8 81 f1 b7 1d c1 04 85 d2 0f 49 c8 8d 04 09 8b d0 81 f2 b7 1d c1 04 85 c9 0f 49 d0 8d 04 12 8b c8 81 f1 b7 1d c1 04 85 d2 0f 49 c8 8d 04 09 8b d0 81 f2 b7 1d c1 04 85 c9 0f 49 d0 8d 04 12 8b c8 81 f1 b7 1d c1 04 85 d2 0f 49 c8 8d 04 09 8b d0 81 f2 b7 1d c1 04 85 c9 0f 49 d0 8d 0c 12 8b c1 35 b7 1d c1 04 85 d2 0f 49 c1 49 ff c2 4d 3b d1 } //5
		$a_01_2 = {4d 70 6f 61 66 41 4b 4f 44 56 53 6e 61 69 } //3 MpoafAKODVSnai
		$a_01_3 = {44 44 44 20 2a 2a 2a 2a 20 31 32 33 } //2 DDD **** 123
		$a_01_4 = {4d 4d 4d 20 2a 2a 2a 2a 20 35 36 37 } //1 MMM **** 567
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=11
 
}