
rule TrojanSpy_Win32_Logsnif{
	meta:
		description = "TrojanSpy:Win32/Logsnif,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_00_0 = {80 78 01 00 74 07 80 38 00 74 fb eb ed fe 40 01 53 56 57 50 8c da 64 8b 0d 30 00 00 00 f6 c2 04 be } //3
		$a_00_1 = {75 73 ba 6c 02 fe 7f 8a 22 80 fc 04 8a 42 04 72 05 80 fc 05 76 04 66 b8 33 03 c1 e0 10 66 b8 00 01 ab 8b 51 0c 8b 42 1c 8b 58 08 b8 } //3
		$a_00_2 = {66 b8 0a 84 bb 00 00 f7 bf 80 fa 60 73 02 b0 03 ba } //3
		$a_00_3 = {4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 5c 6d 73 69 6d 6e 2e 65 78 65 } //1 Outlook Express\msimn.exe
		$a_00_4 = {52 61 64 69 6d 20 50 69 63 68 61 } //1 Radim Picha
		$a_01_5 = {50 72 6f 67 72 61 6d 46 69 6c 65 73 44 69 72 } //1 ProgramFilesDir
		$a_00_6 = {45 6c 69 52 54 } //1 EliRT
		$a_00_7 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 \shell\open\command
		$a_00_8 = {45 38 50 69 52 7a 4a 6d 6f 43 73 37 68 48 33 30 6c 50 72 6a } //1 E8PiRzJmoCs7hH30lPrj
		$a_00_9 = {53 6f 66 74 77 61 72 65 5c 41 64 6f 62 65 5c 53 55 42 47 } //1 Software\Adobe\SUBG
		$a_00_10 = {4e 74 4f 70 65 6e 54 68 72 65 61 64 } //1 NtOpenThread
		$a_01_11 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_00_12 = {53 65 74 54 68 72 65 61 64 41 66 66 69 6e 69 74 79 4d 61 73 6b } //1 SetThreadAffinityMask
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_01_11  & 1)*1+(#a_00_12  & 1)*1) >=13
 
}