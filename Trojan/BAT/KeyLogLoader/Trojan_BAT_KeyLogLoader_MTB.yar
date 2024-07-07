
rule Trojan_BAT_KeyLogLoader_MTB{
	meta:
		description = "Trojan:BAT/KeyLogLoader!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
		$a_01_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //1 LoadLibraryA
		$a_01_2 = {49 4d 50 4f 52 54 41 4e 54 5f 46 49 4c 45 } //1 IMPORTANT_FILE
		$a_01_3 = {49 6e 6a 65 63 74 50 45 } //1 InjectPE
		$a_01_4 = {47 65 74 50 72 6f 63 65 73 73 42 79 49 64 } //1 GetProcessById
		$a_01_5 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_6 = {73 65 74 5f 46 69 6c 65 4e 61 6d 65 } //1 set_FileName
		$a_01_7 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_01_8 = {52 65 67 69 73 74 72 79 4b 65 79 50 65 72 6d 69 73 73 69 6f 6e 43 68 65 63 6b } //1 RegistryKeyPermissionCheck
		$a_01_9 = {43 72 65 61 74 65 50 72 6f 6a 65 63 74 45 72 72 6f 72 } //1 CreateProjectError
		$a_01_10 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64GetThreadContext
		$a_01_11 = {57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64SetThreadContext
		$a_01_12 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //1 set_CreateNoWindow
		$a_01_13 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_14 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_15 = {53 6b 69 70 56 65 72 69 66 69 63 61 74 69 6f 6e } //1 SkipVerification
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}