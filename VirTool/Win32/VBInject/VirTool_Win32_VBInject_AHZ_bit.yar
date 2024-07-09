
rule VirTool_Win32_VBInject_AHZ_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 55 8b ec 83 5b be 00 10 40 00 [0-10] 83 f8 00 74 [0-10] 18 75 [0-10] 81 78 04 ec 0c 56 8d 75 } //1
		$a_01_1 = {51 b9 dd cc bb aa d9 d0 e2 fc 59 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}