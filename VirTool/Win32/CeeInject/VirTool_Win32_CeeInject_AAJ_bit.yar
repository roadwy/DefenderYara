
rule VirTool_Win32_CeeInject_AAJ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 14 bf 8b 8c 24 90 01 03 00 0f af cb 0f af 8c 24 90 01 03 00 03 d1 8b 84 24 90 01 03 00 33 c7 0f af fa 88 06 90 00 } //1
		$a_03_1 = {0f b6 06 89 84 24 90 01 03 00 89 8c 24 90 01 03 00 8d 84 1f 8a 00 00 00 0f af c2 89 84 24 90 01 03 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}