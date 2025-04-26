
rule VirTool_Win32_VBInject_AHK_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHK!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 2e 92 0f 00 [0-20] 05 28 6e 32 00 [0-20] 39 41 04 75 [0-20] 68 cd 7b 34 00 [0-20] 58 [0-20] 05 80 84 1e 00 [0-20] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}