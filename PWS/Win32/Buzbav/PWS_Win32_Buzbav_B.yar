
rule PWS_Win32_Buzbav_B{
	meta:
		description = "PWS:Win32/Buzbav.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 57 b9 40 00 00 00 33 c0 8d 7c 24 ?? c6 44 24 ?? 00 f3 ab 66 ab aa b9 ff 01 00 00 33 c0 8d bc 24 ?? 01 00 00 c6 84 24 ?? 01 00 00 00 f3 ab 66 ab aa b9 ?? 00 00 00 } //1
		$a_02_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c [0-10] 2e 64 6c 6c [0-10] 53 45 52 56 45 52 [0-15] 40 65 78 69 74 00 40 64 65 6c [0-30] 2e 61 71 71 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule PWS_Win32_Buzbav_B_2{
	meta:
		description = "PWS:Win32/Buzbav.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {53 55 56 57 33 ff 68 ?? ?? 40 00 68 ?? ?? 40 00 c7 05 ?? ?? 40 00 30 00 00 00 c7 05 ?? ?? 40 00 02 00 00 00 c7 05 ?? ?? 40 00 05 00 00 00 89 3d ?? ?? 40 00 89 3d ?? ?? 40 00 89 3d ?? ?? 40 00 89 3d ?? ?? 40 00 ff 15 ?? ?? 40 00 8b 1d ?? ?? 40 00 bd 04 00 00 00 68 ?? ?? 40 00 50 a3 ?? ?? 40 00 89 2d ?? ?? 40 00 ff d3 a1 ?? ?? 40 00 33 f6 3b c5 75 ?? 8b 2d ?? ?? 40 00 57 68 ?? ?? 40 00 } //1
		$a_02_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c [0-10] 2e 64 6c 6c [0-05] 50 72 6f 67 4d 61 6e [0-05] 58 59 74 65 73 74 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule PWS_Win32_Buzbav_B_3{
	meta:
		description = "PWS:Win32/Buzbav.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {57 57 50 56 ff 15 ?? ?? 00 10 8d 44 24 ?? 57 50 8d [0-06] 68 00 02 00 00 51 56 ff 15 ?? ?? 00 10 [0-08] 8b 35 ?? ?? 00 10 [0-05] 8d [0-06] 68 ?? ?? 00 10 52 ff d6 83 c4 08 85 c0 75 09 ?? 81 ?? fe 01 00 00 } //2
		$a_00_1 = {61 3d 25 73 26 70 3d 25 73 26 67 3d 25 73 26 73 3d 25 73 26 6e 3d 25 73 26 6c 3d 25 73 } //1 a=%s&p=%s&g=%s&s=%s&n=%s&l=%s
		$a_00_2 = {42 5a 42 41 56 53 4d 54 } //1 BZBAVSMT
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}