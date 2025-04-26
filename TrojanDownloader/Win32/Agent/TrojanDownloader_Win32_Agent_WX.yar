
rule TrojanDownloader_Win32_Agent_WX{
	meta:
		description = "TrojanDownloader:Win32/Agent.WX,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 0c 00 00 "
		
	strings :
		$a_00_0 = {54 69 74 6c 65 20 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 } //2 Title Windows Update
		$a_00_1 = {40 64 65 6c 20 25 31 20 3e 6e 75 6c } //1 @del %1 >nul
		$a_00_2 = {40 63 6c 73 } //1 @cls
		$a_00_3 = {40 76 65 72 } //1 @ver
		$a_00_4 = {40 69 66 20 65 78 69 73 74 20 25 31 20 67 6f 74 6f 20 64 } //1 @if exist %1 goto d
		$a_00_5 = {40 64 65 6c 20 25 30 61 2e 62 61 74 20 43 3a 5c 6d 79 61 70 70 2e 65 78 65 } //1 @del %0a.bat C:\myapp.exe
		$a_00_6 = {73 76 63 68 6f 73 74 2e 65 78 65 } //1 svchost.exe
		$a_01_7 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 } //1 GetModuleFileNameA
		$a_00_8 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //1 VirtualProtectEx
		$a_01_9 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_10 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
		$a_00_11 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=12
 
}