
rule Worm_Win32_Wogue_A{
	meta:
		description = "Worm:Win32/Wogue.A,SIGNATURE_TYPE_PEHSTR,15 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 65 62 79 65 31 36 33 2e 63 6e 2f 68 7a } //10 http://webye163.cn/hz
		$a_01_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 49 4f 2e 70 69 66 } //10 shellexecute=IO.pif
		$a_01_2 = {4e 65 74 20 53 74 6f 70 20 4e 6f 72 74 6f 6e 20 41 6e 74 69 76 69 72 75 73 20 41 75 74 6f 20 50 72 6f 74 65 63 74 20 53 65 72 76 69 63 65 } //1 Net Stop Norton Antivirus Auto Protect Service
		$a_01_3 = {4e 65 74 20 53 74 6f 70 20 6d 63 73 68 69 65 6c 64 } //1 Net Stop mcshield
		$a_01_4 = {6e 65 74 20 73 74 6f 70 20 22 57 69 6e 64 6f 77 73 20 46 69 72 65 77 61 6c 6c 2f 49 6e 74 65 72 6e 65 74 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 53 68 61 72 69 6e 67 20 28 49 43 53 29 22 } //1 net stop "Windows Firewall/Internet Connection Sharing (ICS)"
		$a_01_5 = {6e 65 74 20 73 74 6f 70 20 53 79 73 74 65 6d 20 52 65 73 74 6f 72 65 20 53 65 72 76 69 63 65 } //1 net stop System Restore Service
		$a_01_6 = {44 69 72 65 63 74 58 31 30 2e 64 6c 6c } //10 DirectX10.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10) >=12
 
}