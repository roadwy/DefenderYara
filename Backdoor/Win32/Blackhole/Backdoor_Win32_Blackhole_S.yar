
rule Backdoor_Win32_Blackhole_S{
	meta:
		description = "Backdoor:Win32/Blackhole.S,SIGNATURE_TYPE_PEHSTR_EXT,ffffffbb 00 ffffffbb 00 11 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4b 65 79 2e 64 6c 6c } //100 GetKey.dll
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_2 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //10 FPUMaskValue
		$a_01_3 = {53 74 61 72 74 48 6f 6f 6b } //10 StartHook
		$a_00_4 = {53 74 6f 70 48 6f 6f 6b } //10 StopHook
		$a_00_5 = {57 72 69 74 65 46 69 6c 65 } //5 WriteFile
		$a_01_6 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //5 UnmapViewOfFile
		$a_01_7 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //5 MapViewOfFile
		$a_00_8 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //5 FindFirstFileA
		$a_01_9 = {43 72 65 61 74 65 46 69 6c 65 4d 61 70 70 69 6e 67 41 } //5 CreateFileMappingA
		$a_00_10 = {43 72 65 61 74 65 46 69 6c 65 41 } //5 CreateFileA
		$a_00_11 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //5 UnhookWindowsHookEx
		$a_01_12 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //5 SetWindowsHookExA
		$a_00_13 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //5 CallNextHookEx
		$a_01_14 = {55 6e 69 74 5f 44 6c 6c 4d 61 69 6e } //1 Unit_DllMain
		$a_01_15 = {47 65 74 4b 65 79 00 } //1
		$a_01_16 = {5f 6b 61 73 70 65 72 73 6b 79 } //2 _kaspersky
	condition:
		((#a_01_0  & 1)*100+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_00_8  & 1)*5+(#a_01_9  & 1)*5+(#a_00_10  & 1)*5+(#a_00_11  & 1)*5+(#a_01_12  & 1)*5+(#a_00_13  & 1)*5+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*2) >=187
 
}