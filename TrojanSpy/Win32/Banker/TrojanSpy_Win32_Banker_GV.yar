
rule TrojanSpy_Win32_Banker_GV{
	meta:
		description = "TrojanSpy:Win32/Banker.GV,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //1 FPUMaskValue
		$a_01_1 = {5c 44 6f 77 6e 6c 6f 61 64 65 64 20 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 2a 67 62 2a 2e 2a } //1 \Downloaded Program Files\*gb*.*
		$a_01_2 = {5c 47 62 50 6c 75 67 69 6e 5c 2a 2e 2a } //1 \GbPlugin\*.*
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e 00 00 00 ff ff ff ff 08 00 00 00 65 78 70 6c 6f 72 65 72 } //1
		$a_01_4 = {70 72 6f 67 72 61 6d 66 69 6c 65 73 00 } //1
		$a_01_5 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_6 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_7 = {42 6d 73 41 70 69 48 6f 6f 6b } //1 BmsApiHook
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}