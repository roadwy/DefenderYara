
rule Backdoor_Win32_Caphaw_U{
	meta:
		description = "Backdoor:Win32/Caphaw.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {a9 00 00 f0 00 74 44 81 7d d4 47 65 6e 75 75 3b 81 7d d8 69 6e 65 49 75 32 81 7d dc 6e 74 65 6c 75 29 8b 45 e0 25 00 00 00 10 8b 4d f0 64 89 0d 00 00 00 00 } //1
		$a_01_1 = {8b 46 50 6a 40 50 53 ff d7 64 a1 10 00 00 00 8b 4e 50 6a 40 68 00 10 00 00 51 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Backdoor_Win32_Caphaw_U_2{
	meta:
		description = "Backdoor:Win32/Caphaw.U,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {99 81 e2 ff 1f 00 00 55 03 c2 8b e8 c1 fd 0d 85 ed } //4
		$a_01_1 = {0f b6 d6 33 dd 0f b6 69 0e 0f b6 49 0f c1 e3 08 33 dd 8b 68 0c c1 e3 08 33 d9 } //4
		$a_03_2 = {4b 65 79 00 53 65 74 00 [0-10] 45 72 72 6f 72 20 25 69 00 } //2
		$a_01_3 = {51 2b d3 50 03 d0 ff d2 } //1
		$a_01_4 = {52 2b c3 55 03 c5 ff d0 } //1
		$a_01_5 = {2b d3 0f af c2 03 c6 ff d0 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=11
 
}