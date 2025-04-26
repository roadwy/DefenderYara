
rule TrojanDropper_Win32_DelfInject_A{
	meta:
		description = "TrojanDropper:Win32/DelfInject.A,SIGNATURE_TYPE_PEHSTR,2c 00 2c 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 63 2e 65 78 65 } //10 calc.exe
		$a_01_1 = {62 79 20 73 68 6f 6f 6f 6f } //10 by shoooo
		$a_01_2 = {54 65 31 65 70 68 6f 6e 79 2e 65 78 65 } //10 Te1ephony.exe
		$a_01_3 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //10 explorerbar
		$a_01_4 = {54 72 61 6e 73 6d 69 74 46 69 6c 65 } //1 TransmitFile
		$a_01_5 = {45 6e 75 6d 50 72 6f 63 65 73 73 65 73 } //1 EnumProcesses
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_7 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=44
 
}