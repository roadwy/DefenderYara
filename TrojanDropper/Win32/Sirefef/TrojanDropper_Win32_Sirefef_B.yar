
rule TrojanDropper_Win32_Sirefef_B{
	meta:
		description = "TrojanDropper:Win32/Sirefef.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 70 58 85 f6 75 ?? be 53 50 43 33 e8 } //1
		$a_00_1 = {b8 00 51 00 00 66 89 44 24 30 b8 00 52 00 00 66 89 44 24 32 b8 00 50 00 00 66 89 44 24 34 b8 73 72 00 00 66 89 44 24 36 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule TrojanDropper_Win32_Sirefef_B_2{
	meta:
		description = "TrojanDropper:Win32/Sirefef.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {81 f1 2e 8e 40 42 35 47 42 ca 72 89 4d f0 8b 0d ?? ?? 40 00 89 45 ec a1 ?? ?? 40 00 81 f1 0a 30 76 9d 35 88 b3 5e bb 89 4d f8 32 c9 } //1
		$a_02_1 = {01 00 00 9d 90 90 68 ?? ?? 41 00 6a 00 6a 00 68 ?? ?? 41 00 6a fe ff 15 ?? ?? 41 00 } //1
		$a_00_2 = {5a 77 51 75 65 75 65 41 70 63 54 68 72 65 61 64 } //1 ZwQueueApcThread
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDropper_Win32_Sirefef_B_3{
	meta:
		description = "TrojanDropper:Win32/Sirefef.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_03_0 = {8b f8 3b fe 74 42 53 68 ?? ?? ?? ?? 6a fc 57 ff 15 ?? ?? ?? ?? 6a 01 57 } //3
		$a_01_1 = {83 7d 0c 18 } //3
		$a_01_2 = {8b c4 53 6a 20 83 c0 f0 50 ff 15 } //1
		$a_01_3 = {8b dc 8d 47 60 50 6a 20 83 c3 f0 53 ff 15 } //1
		$a_01_4 = {8b fc 8d 43 60 50 6a 20 83 c7 f0 57 ff 15 } //1
		$a_01_5 = {8b f4 8d 47 60 50 6a 20 83 c6 f0 56 ff 15 } //1
		$a_01_6 = {8d 48 28 8b 40 14 c1 e8 02 8b 54 24 08 31 11 83 c1 04 48 75 f4 } //5
		$a_03_7 = {8b 48 fc 83 c0 28 4a f3 a4 75 ea 33 c0 8d bd ?? ?? ?? ?? b9 ?? ?? ?? ?? f3 ab c7 85 ?? ?? ?? ?? 10 00 01 00 c7 } //7
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*5+(#a_03_7  & 1)*7) >=7
 
}
rule TrojanDropper_Win32_Sirefef_B_4{
	meta:
		description = "TrojanDropper:Win32/Sirefef.B,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 48 fc 83 c0 28 4a f3 a4 75 ea 33 c0 8d bd ?? ?? ?? ?? b9 ?? ?? ?? ?? f3 ab c7 85 ?? ?? ?? ?? 10 00 01 00 c7 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}
rule TrojanDropper_Win32_Sirefef_B_5{
	meta:
		description = "TrojanDropper:Win32/Sirefef.B,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 70 58 85 f6 75 ?? be 53 50 43 33 e8 } //1
		$a_00_1 = {b8 00 51 00 00 66 89 44 24 30 b8 00 52 00 00 66 89 44 24 32 b8 00 50 00 00 66 89 44 24 34 b8 73 72 00 00 66 89 44 24 36 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule TrojanDropper_Win32_Sirefef_B_6{
	meta:
		description = "TrojanDropper:Win32/Sirefef.B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {81 f1 2e 8e 40 42 35 47 42 ca 72 89 4d f0 8b 0d ?? ?? 40 00 89 45 ec a1 ?? ?? 40 00 81 f1 0a 30 76 9d 35 88 b3 5e bb 89 4d f8 32 c9 } //1
		$a_02_1 = {01 00 00 9d 90 90 68 ?? ?? 41 00 6a 00 6a 00 68 ?? ?? 41 00 6a fe ff 15 ?? ?? 41 00 } //1
		$a_00_2 = {5a 77 51 75 65 75 65 41 70 63 54 68 72 65 61 64 } //1 ZwQueueApcThread
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}