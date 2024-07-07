
rule VirTool_Win32_VBInject_gen_HQ{
	meta:
		description = "VirTool:Win32/VBInject.gen!HQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 0f 8d 95 20 ff ff ff 52 57 ff 51 14 db e2 3b c6 7d 90 01 01 6a 14 68 90 01 04 57 50 ff 15 90 00 } //1
		$a_00_1 = {3a 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 :\Projekt1.vbp
		$a_00_2 = {56 42 4d 73 6f 53 74 64 43 6f 6d 70 4d 67 72 } //1 VBMsoStdCompMgr
		$a_00_3 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //1 RtlMoveMemory
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}