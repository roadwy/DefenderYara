
rule PWS_Win32_Dyzap_T{
	meta:
		description = "PWS:Win32/Dyzap.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 b8 61 00 00 00 b9 52 00 00 00 57 66 89 45 f0 66 89 4d ec ff 15 } //1
		$a_03_1 = {c6 45 f3 75 c6 45 f7 6a ff 15 ?? ?? ?? ?? 85 c0 74 11 } //1
		$a_01_2 = {ff d0 6a 04 68 00 30 00 00 68 00 00 02 00 6a 00 89 44 24 34 ff 54 24 28 8b f8 } //1
		$a_03_3 = {c6 45 f0 50 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 4d 08 51 6a 00 68 08 04 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}
rule PWS_Win32_Dyzap_T_2{
	meta:
		description = "PWS:Win32/Dyzap.T,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 4d d4 ba 4b 76 41 02 c1 e6 00 c1 ec 00 48 8b 55 dc ff 75 e4 } //1
		$a_03_1 = {c7 85 38 f2 ff ff 73 65 78 65 ff 15 ?? ?? ?? ?? 8d } //1
		$a_01_2 = {74 00 65 00 6d 00 70 00 00 00 00 00 67 00 75 00 70 00 64 00 61 00 74 00 65 00 } //1
		$a_81_3 = {47 6c 6f 62 61 6c 5c 75 31 6e 79 6a 33 72 74 32 30 } //1 Global\u1nyj3rt20
		$a_01_4 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 67 00 32 00 66 00 61 00 62 00 67 00 35 00 37 00 31 00 33 00 } //1 \\.\pipe\g2fabg5713
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule PWS_Win32_Dyzap_T_3{
	meta:
		description = "PWS:Win32/Dyzap.T,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 4d d4 ba 4b 76 41 02 c1 e6 00 c1 ec 00 48 8b 55 dc ff 75 e4 } //1
		$a_01_1 = {8d 45 f4 99 52 50 6a 00 6a 00 8d 45 e4 99 52 8b 55 08 50 51 52 6a 04 56 57 } //1
		$a_01_2 = {74 00 65 00 6d 00 70 00 00 00 00 00 67 00 75 00 70 00 64 00 61 00 74 00 65 00 } //1
		$a_81_3 = {47 6c 6f 62 61 6c 5c 74 31 6e 79 6a 33 72 74 32 30 } //1 Global\t1nyj3rt20
		$a_01_4 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 67 00 32 00 66 00 61 00 62 00 67 00 35 00 37 00 31 00 33 00 } //1 \\.\pipe\g2fabg5713
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}