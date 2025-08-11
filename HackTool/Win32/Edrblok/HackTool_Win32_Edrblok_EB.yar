
rule HackTool_Win32_Edrblok_EB{
	meta:
		description = "HackTool:Win32/Edrblok.EB,SIGNATURE_TYPE_PEHSTR_EXT,2f 00 2f 00 0f 00 00 "
		
	strings :
		$a_01_0 = {87 1e 8e d7 44 86 a5 4e 94 37 d8 09 ec ef c9 71 } //20
		$a_01_1 = {d1 57 8d c3 a7 05 33 4c 90 4f 7f bc ee e6 0e 82 } //10
		$a_01_2 = {3b 39 72 4a 9f 31 bc 44 84 c3 ba 54 dc b3 b6 b4 } //10
		$a_80_3 = {4d 73 4d 70 45 6e 67 } //MsMpEng  1
		$a_80_4 = {4d 73 53 65 6e 73 65 } //MsSense  1
		$a_80_5 = {53 65 6e 73 65 49 52 } //SenseIR  1
		$a_80_6 = {53 65 6e 73 65 4e 64 72 } //SenseNdr  1
		$a_80_7 = {53 65 6e 73 65 43 6e 63 50 72 6f 78 79 } //SenseCncProxy  1
		$a_80_8 = {53 65 6e 73 65 53 61 6d 70 6c 65 55 70 6c 6f 61 64 65 72 } //SenseSampleUploader  1
		$a_80_9 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //SeDebugPrivilege  1
		$a_80_10 = {55 6e 69 74 54 65 73 74 } //UnitTest  -100
		$a_80_11 = {53 65 6e 73 65 43 6f 6d 6d 6f 6e } //SenseCommon  -100
		$a_80_12 = {53 65 6e 73 65 2e 43 6f 6d 6d 6f 6e } //Sense.Common  -100
		$a_80_13 = {42 61 72 72 61 63 75 64 61 } //Barracuda  -100
		$a_80_14 = {63 75 64 61 6e 61 63 73 76 63 } //cudanacsvc  -100
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*-100+(#a_80_11  & 1)*-100+(#a_80_12  & 1)*-100+(#a_80_13  & 1)*-100+(#a_80_14  & 1)*-100) >=47
 
}