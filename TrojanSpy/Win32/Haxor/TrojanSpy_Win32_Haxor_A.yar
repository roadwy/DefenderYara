
rule TrojanSpy_Win32_Haxor_A{
	meta:
		description = "TrojanSpy:Win32/Haxor.A,SIGNATURE_TYPE_PEHSTR,22 00 22 00 08 00 00 "
		
	strings :
		$a_01_0 = {49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 } //10 IE(AL("%s",4),"AL(\"%0:s\",3)"
		$a_01_1 = {4a 75 6d 70 49 44 28 22 22 2c 22 25 73 22 29 } //10 JumpID("","%s")
		$a_01_2 = {68 34 78 30 72 6b 69 6c 6c } //10 h4x0rkill
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_4 = {48 65 61 70 33 32 4c 69 73 74 46 69 72 73 74 } //1 Heap32ListFirst
		$a_01_5 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
		$a_01_6 = {54 68 72 65 61 64 47 65 72 61 6c } //1 ThreadGeral
		$a_01_7 = {54 68 72 65 61 64 44 65 6c 65 74 61 } //1 ThreadDeleta
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=34
 
}