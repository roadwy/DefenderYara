
rule Backdoor_Win32_Farfli_I{
	meta:
		description = "Backdoor:Win32/Farfli.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a c2 8b fe 2c 90 01 01 83 c9 ff d0 e0 00 04 32 33 c0 42 f2 ae f7 d1 49 3b d1 72 e6 90 00 } //2
		$a_01_1 = {c6 45 d4 5c c6 45 d5 62 c6 45 d6 65 c6 45 d7 65 c6 45 d8 70 c6 45 d9 2e c6 45 da 73 c6 45 db 79 c6 45 dc 73 } //3
		$a_03_2 = {33 c0 80 b0 90 01 05 40 3d 90 01 04 7c f1 33 c0 c3 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2) >=3
 
}
rule Backdoor_Win32_Farfli_I_2{
	meta:
		description = "Backdoor:Win32/Farfli.I,SIGNATURE_TYPE_PEHSTR_EXT,35 00 35 00 09 00 00 "
		
	strings :
		$a_00_0 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //10 shell\open\command
		$a_00_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //10 SYSTEM\CurrentControlSet\Services\%s
		$a_01_2 = {53 65 72 76 69 63 65 44 6c 6c 00 } //10
		$a_00_3 = {53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //10 System32\svchost.exe -k netsvcs
		$a_00_4 = {47 6c 6f 62 61 6c 5c 47 68 30 73 74 } //10 Global\Gh0st
		$a_00_5 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 } //1 SYSTEM\CurrentControlSet\Services\BITS
		$a_00_6 = {5c 5c 2e 5c 4d 49 4e 49 53 41 46 45 44 4f 53 } //1 \\.\MINISAFEDOS
		$a_00_7 = {53 4f 46 54 57 41 52 45 5c 4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 57 6d 69 48 6c 70 5c 7b 32 43 34 44 34 42 43 36 2d 30 37 39 33 2d 34 39 35 36 2d 41 39 46 39 2d 45 32 35 32 34 33 35 34 36 39 43 30 7d } //1 SOFTWARE\KasperskyLab\WmiHlp\{2C4D4BC6-0793-4956-A9F9-E252435469C0}
		$a_00_8 = {43 56 69 64 65 6f 43 61 70 } //1 CVideoCap
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=53
 
}