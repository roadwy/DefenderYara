
rule VirTool_Win32_VBInject_AJN_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 fa 41 41 41 41 0f 85 ?? ?? ff ff 90 0a 40 00 5e 90 0a 40 00 33 14 24 } //1
		$a_03_1 = {8b 80 cc 10 00 00 [0-30] 6a 47 [0-30] 83 2c 24 07 [0-30] 68 02 10 00 00 [0-30] 83 2c 24 02 [0-30] 68 00 62 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}