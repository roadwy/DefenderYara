
rule VirTool_Win32_DelfInject_gen_BY{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 03 8d 04 80 99 03 04 24 13 54 24 04 83 c4 08 8b 55 90 01 01 03 d0 8d 85 90 01 02 ff ff b9 28 00 00 00 90 00 } //1
		$a_03_1 = {b9 00 04 00 00 8d 85 90 01 02 ff ff e8 90 01 04 e8 90 01 04 8b c7 8b 55 f8 e8 90 01 04 2b 75 f4 81 fe 00 90 03 01 02 04 90 90 00 00 7f bb 90 00 } //1
		$a_03_2 = {b9 f8 00 00 00 e8 90 01 04 81 bd 90 01 02 ff ff 50 45 00 00 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}