
rule TrojanDropper_Win32_Agent_TS{
	meta:
		description = "TrojanDropper:Win32/Agent.TS,SIGNATURE_TYPE_PEHSTR_EXT,3d 00 3d 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 72 65 65 20 44 4c 4c 20 44 6f 6e 65 21 } //10 Free DLL Done!
		$a_00_1 = {53 65 72 76 69 63 65 44 6c 6c 00 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 5c 50 61 72 61 6d 65 74 65 72 73 } //10
		$a_01_2 = {53 74 61 72 74 20 44 4c 4c 20 53 65 72 76 69 63 65 3a } //10 Start DLL Service:
		$a_01_3 = {41 6e 73 6b 79 61 } //1 Anskya
		$a_01_4 = {73 68 65 77 6f 71 69 73 68 75 69 } //1 shewoqishui
		$a_00_5 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //10 GetSystemDirectoryA
		$a_00_6 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //10 OpenSCManagerA
		$a_00_7 = {43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 41 } //10 ChangeServiceConfigA
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10) >=61
 
}