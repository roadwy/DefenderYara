
rule PWS_Win32_Skatayo_A{
	meta:
		description = "PWS:Win32/Skatayo.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 07 00 00 "
		
	strings :
		$a_02_0 = {c8 f0 d0 c7 d7 a2 b2 e1 b1 ed bc e0 bf d8 cc e1 ca be [0-10] 23 33 32 37 37 30 } //5
		$a_02_1 = {cd ac d2 e2 d0 de b8 c4 [0-10] 42 75 74 74 6f 6e } //5
		$a_00_2 = {69 66 20 65 78 69 73 74 73 20 22 } //2 if exists "
		$a_00_3 = {67 6f 74 6f 20 74 72 79 } //2 goto try
		$a_00_4 = {41 73 6b 54 61 6f 2e } //2 AskTao.
		$a_00_5 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 Explorer.exe
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=12
 
}
rule PWS_Win32_Skatayo_A_2{
	meta:
		description = "PWS:Win32/Skatayo.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_00_1 = {25 73 3f 73 3d 25 73 26 71 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 26 73 70 3d 25 73 26 72 3d 25 73 26 6c 3d 25 73 } //3 %s?s=%s&q=%s&u=%s&p=%s&sp=%s&r=%s&l=%s
		$a_00_2 = {2f 6c 69 6e 2e 61 73 70 } //2 /lin.asp
		$a_00_3 = {61 73 6b 74 61 6f 2e } //2 asktao.
		$a_00_4 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 } //2 Explorer.exe
		$a_01_5 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //2 CreateRemoteThread
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*3+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=12
 
}