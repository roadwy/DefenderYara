
rule VirTool_Win32_VBInject_CB{
	meta:
		description = "VirTool:Win32/VBInject.CB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 5f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 56 00 42 00 5c 00 } //01 00  \_loaderVB\
		$a_01_1 = {73 46 69 6c 65 4e 61 6d 65 00 00 00 6c 70 42 79 74 65 00 00 55 73 65 72 4b 65 79 00 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 } //00 00  桓汥䕬數畣整A
	condition:
		any of ($a_*)
 
}