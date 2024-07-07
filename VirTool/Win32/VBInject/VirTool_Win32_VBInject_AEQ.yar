
rule VirTool_Win32_VBInject_AEQ{
	meta:
		description = "VirTool:Win32/VBInject.AEQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 0c bf 74 23 11 00 c7 46 34 04 00 00 00 39 7e 34 7f 35 } //1
		$a_01_1 = {8b 46 54 c7 80 c0 03 00 00 16 9e 8d 57 8b 46 54 c7 80 50 0b 00 00 9d d6 77 34 8b 46 54 c7 80 6c 10 00 00 6a 51 1c 3e 8b 46 54 c7 80 04 0d 00 00 4b 2f 9c 41 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}