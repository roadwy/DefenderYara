
rule TrojanSpy_Win32_Banker_GT{
	meta:
		description = "TrojanSpy:Win32/Banker.GT,SIGNATURE_TYPE_PEHSTR_EXT,39 00 38 00 09 00 00 "
		
	strings :
		$a_01_0 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //10 FPUMaskValue
		$a_01_1 = {4d 53 4e 53 59 54 45 4d 00 } //10
		$a_01_2 = {6d 73 6e 5f 6c 69 76 65 72 73 00 } //10
		$a_01_3 = {5c 6d 73 6e 6d 73 67 72 2e 65 78 65 } //10 \msnmsgr.exe
		$a_01_4 = {41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //5 ActivateKeyboardLayout
		$a_01_5 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //5 GetWindowThreadProcessId
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //5 CreateToolhelp32Snapshot
		$a_01_7 = {41 41 5f 64 6f 4d 53 4e 54 69 6d 65 72 } //1 AA_doMSNTimer
		$a_01_8 = {4c 69 73 74 61 4d 53 4e 45 6e 76 69 61 72 } //1 ListaMSNEnviar
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=56
 
}