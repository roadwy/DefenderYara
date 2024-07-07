
rule VirTool_Win32_CeeInject_UN_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UN!bit,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {ff ff ff 30 06 c3 } //2
		$a_01_1 = {b8 fd 43 03 00 } //2
		$a_01_2 = {b8 ff 7f 00 00 } //2
		$a_03_3 = {8b c8 0f af 0d 90 01 04 e8 90 01 04 8d 54 01 01 89 15 90 01 04 e8 90 01 04 0f b7 0d 90 01 04 23 c1 c3 90 00 } //1
		$a_03_4 = {8b c8 0f af 0d 90 01 04 e8 90 01 04 03 c8 89 0d 90 01 04 e8 90 01 04 0f b7 15 90 01 04 23 c2 c3 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=7
 
}