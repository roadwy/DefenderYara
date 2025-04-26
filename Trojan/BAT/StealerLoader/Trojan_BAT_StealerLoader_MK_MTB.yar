
rule Trojan_BAT_StealerLoader_MK_MTB{
	meta:
		description = "Trojan:BAT/StealerLoader.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_80_0 = {52 75 6e 50 45 5c 6f 62 6a 5c 44 65 62 75 67 5c 52 75 6e 50 45 2e 70 64 62 } //RunPE\obj\Debug\RunPE.pdb  1
		$a_80_1 = {67 65 74 5f 41 53 43 49 49 } //get_ASCII  1
		$a_80_2 = {47 65 74 50 72 6f 63 65 73 73 42 79 49 64 } //GetProcessById  1
		$a_80_3 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //get_Assembly  1
		$a_80_4 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //get_WebServices  1
		$a_80_5 = {67 65 74 5f 4d 6f 64 75 6c 65 73 } //get_Modules  1
		$a_80_6 = {52 75 6e 50 45 2e 52 65 73 6f 75 72 63 65 73 } //RunPE.Resources  1
		$a_80_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //WriteProcessMemory  1
		$a_80_8 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //ResumeThread  1
		$a_80_9 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //NtUnmapViewOfSection  1
		$a_80_10 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //ReadProcessMemory  1
		$a_80_11 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //GetThreadContext  1
		$a_80_12 = {57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //Wow64SetThreadContext  1
		$a_80_13 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
		$a_80_14 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //LoadLibraryA  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1) >=15
 
}