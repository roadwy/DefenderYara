
rule HackTool_Win64_Edrblok_YAC_MTB{
	meta:
		description = "HackTool:Win64/Edrblok.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 77 70 6d 45 6e 67 69 6e 65 4f 70 65 6e 30 } //1 FwpmEngineOpen0
		$a_01_1 = {62 6c 6f 63 6b 65 64 72 } //1 blockedr
		$a_01_2 = {75 6e 62 6c 6f 63 6b 61 6c 6c } //1 unblockall
		$a_01_3 = {75 6e 62 6c 6f 63 6b } //1 unblock
		$a_03_4 = {48 b8 3b 39 72 4a 9f 31 bc 44 4c 8b 4c 24 ?? 48 89 84 24 20 01 00 00 48 b8 84 c3 ba 54 dc b3 b6 b4 } //10
		$a_03_5 = {d1 57 8d c3 a7 05 33 4c 48 89 84 24 ?? ?? ?? ?? 48 b8 90 90 4f 7f bc ee e6 0e 82 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*10+(#a_03_5  & 1)*10) >=24
 
}