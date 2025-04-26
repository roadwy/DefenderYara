
rule VirTool_Win32_VBInject_VK_bit{
	meta:
		description = "VirTool:Win32/VBInject.VK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 04 08 00 00 00 00 [0-20] 11 14 08 [0-40] 3b 8d 9a 00 00 00 75 [0-20] ff e0 } //1
		$a_03_1 = {81 38 55 8b ec 83 75 ?? [0-20] 81 78 04 ec 0c 56 8d 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}