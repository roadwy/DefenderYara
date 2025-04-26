
rule Backdoor_Win32_Farfli_Q{
	meta:
		description = "Backdoor:Win32/Farfli.Q,SIGNATURE_TYPE_PEHSTR_EXT,12 00 10 00 09 00 00 "
		
	strings :
		$a_03_0 = {83 c9 ff 33 c0 f2 ae f7 d1 49 bf ?? ?? 01 10 8b d1 83 c9 ff f2 ae f7 d1 49 8d 44 0a 01 50 e8 } //4
		$a_01_1 = {b9 81 00 00 00 33 c0 8d bc 24 1d 02 00 00 88 9c 24 1c 02 00 00 f3 ab 66 ab aa 8d 44 24 10 53 50 8d 8c 24 24 02 00 00 68 08 02 00 00 51 56 89 5c 24 24 ff 15 } //4
		$a_01_2 = {f7 e3 2b da 83 c4 04 d1 eb 03 da 83 e1 03 c1 eb 05 f3 a4 0f } //4
		$a_01_3 = {7a 68 6f 6e 67 6a 69 65 } //2 zhongjie
		$a_01_4 = {4e 65 74 2d 54 65 6d 70 2e 69 6e 69 } //2 Net-Temp.ini
		$a_01_5 = {63 3a 5c 4e 54 5f 50 61 74 68 2e 6f 6c 64 } //2 c:\NT_Path.old
		$a_01_6 = {4d 79 20 57 69 6e 33 32 20 41 70 70 6c 61 63 74 69 6f 6e } //2 My Win32 Applaction
		$a_01_7 = {5c 73 79 73 6c 6f 67 2e 64 61 74 } //2 \syslog.dat
		$a_01_8 = {5b 25 30 32 75 2d 25 30 32 75 2d 25 64 20 25 30 32 75 3a 25 30 32 75 3a 25 30 32 75 5d 20 28 25 73 29 } //2 [%02u-%02u-%d %02u:%02u:%02u] (%s)
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=16
 
}