
rule VirTool_Win32_CeeInject_MH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 04 37 8d 3c c7 03 3d 90 01 04 03 fe 03 ff 90 00 } //1
		$a_03_1 = {88 0f 33 c9 41 2b 8d 90 01 04 8b d3 0f af 95 90 01 04 2b c8 0f af ce 2b ca 0f af cb c1 e0 02 03 c8 0f af 8d 90 01 04 29 8d 90 01 04 ff 85 90 01 04 8b 85 90 01 04 3b 45 90 01 01 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}