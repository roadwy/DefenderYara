
rule HackTool_Win32_Edrblok_B{
	meta:
		description = "HackTool:Win32/Edrblok.B,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 0b 00 00 "
		
	strings :
		$a_80_0 = {46 57 50 4d 5f 4c 41 59 45 52 5f 41 4c 45 5f 41 55 54 48 5f 43 4f 4e 4e 45 43 54 5f 56 34 } //FWPM_LAYER_ALE_AUTH_CONNECT_V4  5
		$a_80_1 = {46 57 50 5f 41 43 54 49 4f 4e 5f 42 4c 4f 43 4b } //FWP_ACTION_BLOCK  5
		$a_80_2 = {4d 73 4d 70 45 6e 67 2e 65 78 65 } //MsMpEng.exe  1
		$a_80_3 = {4d 73 53 65 6e 73 65 2e 65 78 65 } //MsSense.exe  1
		$a_80_4 = {53 65 6e 73 65 49 52 2e 65 78 65 } //SenseIR.exe  1
		$a_80_5 = {53 65 6e 73 65 4e 64 72 2e 65 78 65 } //SenseNdr.exe  1
		$a_80_6 = {53 65 6e 73 65 43 6e 63 50 72 6f 78 79 2e 65 78 65 } //SenseCncProxy.exe  1
		$a_80_7 = {53 65 6e 73 65 53 61 6d 70 6c 65 55 70 6c 6f 61 64 65 72 2e 65 78 65 } //SenseSampleUploader.exe  1
		$a_03_8 = {d1 57 8d c3 ?? ?? ?? ?? a7 05 ?? ?? ?? ?? 33 4c ?? ?? 90 90 4f 7f bc ee e6 0e 82 } //10
		$a_03_9 = {87 1e 8e d7 ?? ?? ?? ?? 44 86 ?? ?? ?? ?? a5 4e ?? ?? 94 37 d8 09 ec ef c9 71 } //10
		$a_03_10 = {3b 39 72 4a ?? ?? ?? ?? 9f 31 ?? ?? ?? ?? bc 44 ?? ?? 84 c3 ba 54 dc b3 b6 b4 } //10
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_03_8  & 1)*10+(#a_03_9  & 1)*10+(#a_03_10  & 1)*10) >=36
 
}