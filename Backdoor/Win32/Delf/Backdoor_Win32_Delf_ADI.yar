
rule Backdoor_Win32_Delf_ADI{
	meta:
		description = "Backdoor:Win32/Delf.ADI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_02_0 = {81 c4 f8 fe ff ff c6 04 24 00 68 ?? ?? ?? ?? 8d 44 24 04 50 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 44 24 04 50 e8 ?? ?? ?? ?? 6a 00 8d 44 24 04 50 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 81 c4 08 01 00 00 c3 } //1
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
		$a_00_2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //1 %SystemRoot%\system32\svchost.exe -k netsvcs
		$a_00_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //1 SYSTEM\CurrentControlSet\Services\
		$a_01_4 = {43 72 65 61 74 65 53 65 72 76 69 63 65 41 } //1 CreateServiceA
		$a_01_5 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //1 StartServiceA
		$a_00_6 = {63 6d 64 20 2f 63 20 64 65 6c 20 43 3a 5c 6d 79 61 70 70 2e 65 78 65 } //1 cmd /c del C:\myapp.exe
		$a_01_7 = {57 69 6e 45 78 65 63 } //1 WinExec
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}