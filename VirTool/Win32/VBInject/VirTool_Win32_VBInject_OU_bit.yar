
rule VirTool_Win32_VBInject_OU_bit{
	meta:
		description = "VirTool:Win32/VBInject.OU!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 75 90 02 20 0f 6e 90 02 20 0f fe 90 02 20 8b 90 01 01 28 90 02 20 0f ef 90 02 20 0f 7e 90 00 } //1
		$a_03_1 = {bb 48 00 00 00 90 02 20 83 eb 04 90 02 20 ff 34 1c 90 02 20 58 90 02 20 e8 90 02 20 89 04 1c 90 02 20 85 db 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}