
rule Backdoor_Win32_Unskal_A{
	meta:
		description = "Backdoor:Win32/Unskal.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {8a 03 3c 5e 0f 94 c2 74 08 3c 3d 0f 85 f5 00 00 00 8a 43 f0 89 d9 83 e8 34 3c 01 0f 87 e7 00 00 00 84 d2 89 d8 74 31 39 45 e4 } //5
		$a_01_1 = {55 3c 19 89 e5 77 05 83 c0 41 eb 1e 3c 33 77 05 83 c0 47 eb 15 3c 3d 77 05 83 e8 04 eb 0c 3c 3e } //5
		$a_01_2 = {80 fa 19 76 17 89 fa 80 fa 20 74 10 80 fa 2f 74 0b 80 78 01 5e } //5
		$a_01_3 = {50 83 fb 22 0f 84 93 01 00 00 77 67 83 fb 11 77 29 83 fb 10 0f 83 70 03 00 00 83 fb 09 0f 84 e7 00 00 00 83 fb 0d 0f 84 c9 00 00 00 83 fb 08 0f 85 33 02 00 00 } //5
		$a_03_4 = {26 6f 70 3d 25 64 26 69 64 3d 25 73 26 75 69 3d 25 73 26 77 76 3d 25 64 26 ?? ?? 3d 25 73 } //1
		$a_01_5 = {5b 25 73 5d 20 2d 20 5b 25 2e 32 64 2f 25 2e 32 64 2f 25 64 20 25 2e 32 64 3a 25 2e 32 64 3a 25 2e 32 64 5d } //1 [%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]
		$a_01_6 = {80 7d b4 55 0f 84 79 06 00 00 80 7d b4 69 75 19 e9 65 06 00 00 c6 45 b4 64 b1 6c e9 87 01 00 00 c6 45 b4 6f e9 5e 06 00 00 80 7d b4 70 7f 52 80 7d b4 6f 0f 8d f3 00 00 00 80 7d b4 63 74 74 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*5) >=6
 
}