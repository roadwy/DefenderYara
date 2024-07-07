
rule Trojan_Win32_Raccoon_CE_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {6d 69 72 65 6c 61 } //3 mirela
		$a_81_1 = {46 69 6c 75 64 75 6a 6f 76 61 76 61 } //3 Filudujovava
		$a_81_2 = {43 6f 70 79 46 69 6c 65 57 } //3 CopyFileW
		$a_81_3 = {52 65 6c 65 61 73 65 4d 75 74 65 78 } //3 ReleaseMutex
		$a_81_4 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //3 OutputDebugStringA
		$a_81_5 = {4d 6f 76 65 46 69 6c 65 41 } //3 MoveFileA
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}
rule Trojan_Win32_Raccoon_CE_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {64 66 6f 6b 6a 67 6e 73 64 66 6a 69 6e 67 } //3 dfokjgnsdfjing
		$a_81_1 = {6d 65 68 75 67 69 73 61 6a } //3 mehugisaj
		$a_81_2 = {47 65 74 4e 61 6d 65 64 50 69 70 65 49 6e 66 6f } //3 GetNamedPipeInfo
		$a_81_3 = {46 69 6c 6c 43 6f 6e 73 6f 6c 65 4f 75 74 70 75 74 43 68 61 72 61 63 74 65 72 57 } //3 FillConsoleOutputCharacterW
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //3 IsDebuggerPresent
		$a_81_5 = {47 65 74 46 75 6c 6c 50 61 74 68 4e 61 6d 65 57 } //3 GetFullPathNameW
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}