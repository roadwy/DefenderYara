
rule TrojanSpy_Win32_Fucobha_A{
	meta:
		description = "TrojanSpy:Win32/Fucobha.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {25 73 5c 77 64 6d 61 75 64 2e 64 72 76 00 } //1
		$a_01_1 = {00 6d 79 66 75 63 00 } //1
		$a_00_2 = {25 73 2f 74 6d 70 78 6f 72 2e 64 61 74 } //1 %s/tmpxor.dat
		$a_00_3 = {25 73 3f 66 69 6c 65 70 61 74 68 3d 25 73 26 66 69 6c 65 6e 61 6d 65 3d 25 73 } //1 %s?filepath=%s&filename=%s
		$a_00_4 = {53 79 73 74 65 6d 20 56 65 72 73 69 6f 6e 3a 20 25 64 2e 25 64 20 25 73 20 28 42 75 69 6c 64 20 25 64 29 } //1 System Version: %d.%d %s (Build %d)
		$a_00_5 = {25 73 2f 6f 72 64 65 72 2e 64 61 74 } //1 %s/order.dat
		$a_03_6 = {8a 1c 0a 32 5c 35 ?? 46 3b f0 88 19 75 02 33 f6 41 4f 75 ec } //2
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_03_6  & 1)*2) >=6
 
}
rule TrojanSpy_Win32_Fucobha_A_2{
	meta:
		description = "TrojanSpy:Win32/Fucobha.A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 05 00 00 "
		
	strings :
		$a_00_0 = {00 00 25 73 2f 74 6d 70 2e 64 61 74 00 00 } //10
		$a_00_1 = {00 00 48 6f 73 74 4e 61 6d 65 3a 20 25 73 0d 0a 49 50 3a 20 25 73 0d 0a 50 72 6f 78 79 3a 20 25 73 0d 0a 55 73 65 72 3a 20 25 73 0d 0a 53 79 73 74 65 6d 44 69 72 3a 20 25 73 0d 0a 4f 53 20 4c 61 6e 67 75 61 67 65 20 56 65 72 73 69 6f 6e 3a 20 25 64 0d 0a 73 79 73 74 65 6d 20 76 65 72 73 69 6f 6e 3a 20 25 64 2e 25 64 20 25 73 20 28 62 75 69 6c 64 20 25 64 29 0d 0a } //10
		$a_00_2 = {25 73 3f 66 69 6c 65 70 61 74 68 3d 25 73 26 66 69 6c 65 6e 61 6d 65 3d 25 73 } //1 %s?filepath=%s&filename=%s
		$a_00_3 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 68 77 70 2e 65 78 65 } //1 /c taskkill /f /im hwp.exe
		$a_03_4 = {8a 4f 01 83 c7 01 3a cb 75 f6 8b c8 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d [0-04] 00 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*10) >=30
 
}