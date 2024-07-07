
rule Worm_Win32_Agent{
	meta:
		description = "Worm:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 20 73 79 73 20 70 72 6f 63 65 73 73 2e 65 78 65 } //1 system sys process.exe
		$a_01_1 = {77 69 6e 64 6f 77 73 5c 57 69 6e 64 6f 77 73 20 4d 65 64 6f 63 5c } //1 windows\Windows Medoc\
		$a_01_2 = {77 69 6e 64 6f 77 73 5f 64 78 67 63 2e 65 78 65 } //1 windows_dxgc.exe
		$a_01_3 = {43 3a 5c 00 44 3a 5c 00 45 3a 5c 00 46 3a 5c 00 47 3a 5c 00 48 3a 5c 00 6b 3a 5c 00 52 3a 5c 00 53 3a 5c 00 54 3a 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Worm_Win32_Agent_2{
	meta:
		description = "Worm:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {6d 76 75 6d 69 73 63 2e 65 78 65 } //1 mvumisc.exe
		$a_00_1 = {4b 41 45 4e 41 5f 48 4f 4f 4b } //1 KAENA_HOOK
		$a_00_2 = {5a 77 4f 70 65 6e 50 72 6f 63 65 73 73 } //1 ZwOpenProcess
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 4d 53 72 74 6e 5c 76 61 6c 75 65 31 } //1 Software\Microsoft\Windows\CurrentVersion\MSrtn\value1
		$a_01_4 = {61 00 55 00 74 00 6f 00 52 00 75 00 4e 00 2e 00 69 00 4e 00 46 00 } //1 aUtoRuN.iNF
		$a_00_5 = {65 00 63 00 61 00 6c 00 63 00 2e 00 65 00 78 00 65 00 } //1 ecalc.exe
		$a_00_6 = {6e 00 74 00 73 00 70 00 65 00 63 00 64 00 } //1 ntspecd
		$a_00_7 = {77 72 69 74 65 6c 6e 28 66 32 2c 24 24 24 24 2b 73 63 5b 32 34 5d 2b 24 24 24 29 3b 24 29 } //1 writeln(f2,$$$$+sc[24]+$$$);$)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}