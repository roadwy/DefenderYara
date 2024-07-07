
rule PWS_Win32_Cimuz_D{
	meta:
		description = "PWS:Win32/Cimuz.D,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 8b 54 24 04 8a 44 10 ff 8a 54 1d ff 32 c2 88 07 47 43 8b c5 } //4
		$a_01_1 = {8b 45 fc 8b 40 3c 03 45 fc 89 45 e8 8b 45 fc e8 } //1
		$a_01_2 = {53 56 57 55 8b f9 8b ea 8b f0 b8 34 14 14 13 3b 05 } //1
		$a_01_3 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetWindowsDirectoryA
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}