
rule Trojan_Win32_Dridex_ADM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 46 52 67 70 6d 64 6c 77 77 57 64 65 } //FFRgpmdlwwWde  3
		$a_80_1 = {72 70 69 64 65 62 62 66 6c 6c 2e 70 64 62 } //rpidebbfll.pdb  3
		$a_80_2 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  3
		$a_80_3 = {53 48 47 65 74 44 65 73 6b 74 6f 70 46 6f 6c 64 65 72 } //SHGetDesktopFolder  3
		$a_80_4 = {52 65 67 4f 76 65 72 72 69 64 65 50 72 65 64 65 66 4b 65 79 } //RegOverridePredefKey  3
		$a_80_5 = {53 65 74 75 70 44 69 45 6e 75 6d 44 65 76 69 63 65 49 6e 66 6f } //SetupDiEnumDeviceInfo  3
		$a_80_6 = {68 68 6f 6f 65 77 64 61 71 73 78 } //hhooewdaqsx  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_ADM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {45 6e 75 6d 53 79 73 74 65 6d 4c 6f 63 61 6c 65 73 41 } //EnumSystemLocalesA  3
		$a_80_1 = {4d 61 67 6e 65 74 71 75 6f 74 69 65 6e 74 } //Magnetquotient  3
		$a_80_2 = {6e 6f 2e 70 64 62 } //no.pdb  3
		$a_80_3 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //GetWindowsDirectoryA  3
		$a_80_4 = {46 6c 75 73 68 46 69 6c 65 42 75 66 66 65 72 73 } //FlushFileBuffers  3
		$a_80_5 = {53 65 74 43 6f 6e 73 6f 6c 65 43 74 72 6c 48 61 6e 64 6c 65 72 } //SetConsoleCtrlHandler  3
		$a_80_6 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  3
		$a_80_7 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //GetStartupInfoA  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}