
rule PWS_Win32_Frethog_CA{
	meta:
		description = "PWS:Win32/Frethog.CA,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 08 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_02_1 = {33 c9 39 4c 24 08 7e 10 8b 44 24 04 03 c1 80 30 ?? 41 3b 4c 24 08 7c f0 c3 } //10
		$a_00_2 = {c6 45 f0 5d c6 45 f1 4a c6 45 f2 4c c6 45 f3 32 c6 45 f4 5d c6 45 f5 70 c6 45 f6 79 } //10
		$a_00_3 = {00 36 36 39 37 31 38 33 35 00 } //4 㘀㤶ㄷ㌸5
		$a_01_4 = {57 90 90 90 90 90 90 } //3
		$a_00_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_6 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_7 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 55 4e } //1 SoftWare\Microsoft\Windows\CurrentVersion\RUN
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*4+(#a_01_4  & 1)*3+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=25
 
}