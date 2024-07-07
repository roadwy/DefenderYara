
rule PWS_Win32_Frethog_AA{
	meta:
		description = "PWS:Win32/Frethog.AA,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {55 8b ec 83 ec 20 53 56 8d 45 e0 57 50 c7 45 e0 4c 6f 67 69 c7 45 e4 6e 43 74 72 c7 45 e8 6c 2e 64 6c c7 45 ec 6c 00 00 00 ff 15 4c 40 00 10 8b d8 85 db 89 5d f4 74 17 bf 00 00 50 00 57 6a 00 ff 15 04 40 00 10 8b f0 85 f6 89 75 f0 75 07 32 c0 e9 b2 00 00 00 56 ff 15 00 40 00 10 89 75 fc c7 45 f8 00 05 00 00 29 5d fc be 00 10 00 00 8b 45 fc 6a 00 03 c3 56 50 53 ff 35 0c 5a 00 10 ff 15 48 40 00 10 } //10
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_2 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}