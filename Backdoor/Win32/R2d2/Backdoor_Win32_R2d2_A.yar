
rule Backdoor_Win32_R2d2_A{
	meta:
		description = "Backdoor:Win32/R2d2.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 fe ff 74 15 ff 15 ?? ?? ?? ?? 3d b7 00 00 00 74 08 84 db 75 04 b3 01 eb 02 32 db 8b 57 04 56 6a 00 6a 00 6a 06 52 ff 15 } //1
		$a_01_1 = {43 33 50 4f 2d 72 32 64 32 2d 50 4f 45 } //1 C3PO-r2d2-POE
		$a_01_2 = {5c 5c 2e 5c 70 69 70 65 5c 73 61 70 69 70 69 70 65 } //1 \\.\pipe\sapipipe
		$a_01_3 = {53 59 53 21 49 50 43 21 } //1 SYS!IPC!
		$a_01_4 = {5c 5c 2e 5c 4b 65 79 62 6f 61 72 64 43 6c 61 73 73 43 } //1 \\.\KeyboardClassC
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule Backdoor_Win32_R2d2_A_2{
	meta:
		description = "Backdoor:Win32/R2d2.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {1b c0 25 da ff f2 ff 05 3f 00 0f 00 50 6a 00 51 52 ff 15 } //5
		$a_01_1 = {1b c9 8d 44 24 04 81 e1 da ff f2 ff 50 8b 44 24 10 56 81 c1 3f 00 0f 00 6a 00 51 6a 00 6a 00 6a 00 52 50 ff 15 } //5
		$a_01_2 = {44 55 4d 4d 59 21 44 55 4d 4d 59 00 } //1 啄䵍⅙啄䵍Y
		$a_01_3 = {6d 73 6e 6d 73 67 72 2e 65 78 65 } //1 msnmsgr.exe
		$a_01_4 = {53 6b 79 70 65 50 4d 2e 65 78 65 } //1 SkypePM.exe
		$a_01_5 = {79 61 68 6f 6f 6d 65 73 73 65 6e 67 65 72 2e 65 78 65 } //1 yahoomessenger.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}