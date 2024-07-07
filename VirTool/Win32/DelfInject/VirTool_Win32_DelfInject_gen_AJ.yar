
rule VirTool_Win32_DelfInject_gen_AJ{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 00 ff d0 85 c0 74 28 8d 45 e4 50 8b 44 fe 24 e8 90 01 04 50 8b 44 fe 08 50 8b 44 fe 0c 03 45 f0 50 8b 45 c8 50 a1 90 01 04 8b 00 ff d0 43 ff 4d d8 75 a5 90 00 } //1
		$a_03_1 = {8b 45 fc e8 90 01 04 50 8b c3 5a 8b ca 99 f7 f9 8b 45 fc 8a 04 10 88 06 43 46 81 fb 00 01 00 00 75 dd 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}