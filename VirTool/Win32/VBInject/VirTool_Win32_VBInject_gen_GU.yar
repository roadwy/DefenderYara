
rule VirTool_Win32_VBInject_gen_GU{
	meta:
		description = "VirTool:Win32/VBInject.gen!GU,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {c1 f8 1f 33 45 90 01 01 8b 90 03 01 01 4d 8d 90 02 04 c1 f9 1f 33 90 03 01 01 4d 8d 90 02 04 3b c1 90 00 } //3
		$a_03_1 = {8a 1e 32 18 ff 75 90 01 01 8b 45 90 01 01 ff 30 e8 90 01 04 88 18 90 00 } //3
		$a_03_2 = {77 69 6e 73 70 6f 6f 6c 2e 64 72 76 90 01 08 43 6f 6e 66 69 67 75 72 65 50 6f 72 74 41 90 00 } //3
		$a_01_3 = {5c 44 61 72 6b 65 79 65 5c 56 42 36 2e 4f 4c 42 } //10 \Darkeye\VB6.OLB
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_03_2  & 1)*3+(#a_01_3  & 1)*10) >=13
 
}