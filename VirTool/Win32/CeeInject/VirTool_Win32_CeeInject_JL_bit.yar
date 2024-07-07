
rule VirTool_Win32_CeeInject_JL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.JL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 fa 0b 8b c2 c1 e8 1f 03 d0 8a 82 90 01 03 00 32 c1 88 84 15 90 01 03 ff 8a 84 35 90 01 03 ff 3c 3a 77 09 fe c8 88 84 35 90 01 03 ff 90 00 } //1
		$a_03_1 = {6a 00 8d 85 90 01 03 ff ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}