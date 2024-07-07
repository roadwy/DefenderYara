
rule VirTool_Win32_VBInject_AIB_bit{
	meta:
		description = "VirTool:Win32/VBInject.AIB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 54 8b ec 83 5b 43 39 18 75 ef 81 78 04 ec 0c 56 8d 75 } //1
		$a_03_1 = {31 d8 d1 c8 c1 c3 08 e2 f7 90 09 05 00 b9 90 00 } //1
		$a_03_2 = {31 34 0f f8 83 d1 04 81 f9 90 09 05 00 be 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}