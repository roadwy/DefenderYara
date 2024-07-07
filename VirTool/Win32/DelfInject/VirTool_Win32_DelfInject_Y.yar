
rule VirTool_Win32_DelfInject_Y{
	meta:
		description = "VirTool:Win32/DelfInject.Y,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b f0 85 f6 7e 1f bb 01 00 00 00 8d 45 90 01 04 ff ff 8b 55 90 01 01 0f b6 54 1a ff 33 d7 88 54 18 ff 43 4e 75 e6 90 00 } //1
		$a_03_1 = {ff 4b 83 fb 04 75 90 01 0a ff 8b d8 a1 90 01 08 ff 50 b8 90 01 08 ff 50 ff d3 33 c0 5a 59 59 64 89 10 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}