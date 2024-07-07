
rule Trojan_Win32_Dexphot_E_{
	meta:
		description = "Trojan:Win32/Dexphot.E!!Dexphot.E,SIGNATURE_TYPE_ARHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 53 33 db 8b 45 0c 83 f8 11 7f 0c 74 30 83 e8 0f 74 42 48 74 36 eb 48 } //1
		$a_03_1 = {83 e8 16 74 28 2d fa 00 00 00 75 3c 6a 01 68 ff 04 00 00 e8 90 01 02 ff ff 6a 01 68 ff 03 00 00 e8 90 01 02 ff ff eb 22 90 00 } //1
		$a_00_2 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
		$a_00_3 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //1 Process32First
		$a_00_4 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //1 Process32Next
		$a_00_5 = {54 68 72 65 61 64 33 32 46 69 72 73 74 } //1 Thread32First
		$a_00_6 = {54 68 72 65 61 64 33 32 4e 65 78 74 } //1 Thread32Next
		$a_00_7 = {45 6e 75 6d 50 72 6f 63 65 73 73 } //1 EnumProcess
		$a_00_8 = {47 65 74 4d 61 70 70 65 64 46 69 6c 65 4e 61 6d 65 } //1 GetMappedFileName
		$a_00_9 = {47 65 74 44 65 76 69 63 65 44 72 69 76 65 72 42 61 73 65 4e 61 6d 65 } //1 GetDeviceDriverBaseName
		$a_00_10 = {47 65 74 44 65 76 69 63 65 44 72 69 76 65 72 46 69 6c 65 4e 61 6d 65 } //1 GetDeviceDriverFileName
		$a_00_11 = {45 6e 75 6d 44 65 76 69 63 65 44 72 69 76 65 72 73 } //1 EnumDeviceDrivers
		$a_00_12 = {47 65 74 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 49 6e 66 6f } //1 GetProcessMemoryInfo
		$a_01_13 = {78 55 6e 7a 72 54 00 00 ff ff ff ff 02 00 00 00 63 47 00 00 ff ff ff ff 04 00 00 00 39 33 5a 58 00 00 00 00 ff ff ff ff 03 00 00 00 4a 7a 61 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}