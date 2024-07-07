
rule VirTool_Win32_Injector_KP{
	meta:
		description = "VirTool:Win32/Injector.KP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 32 0d 90 01 04 88 08 87 f6 89 f6 89 f6 ff 06 81 3e 90 01 04 75 ae 90 00 } //1
		$a_01_1 = {89 c9 89 ff ff d0 } //1
		$a_03_2 = {ff 06 81 3e 90 01 04 75 f3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}