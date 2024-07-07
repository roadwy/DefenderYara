
rule VirTool_Win32_CeeInject_BAG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BAG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 9d 90 01 03 00 8b c5 0f b6 cb f7 f7 0f be 82 90 01 03 00 03 c6 03 c8 0f b6 f1 8a 86 90 01 03 00 88 85 90 01 03 00 45 88 9e 90 01 03 00 81 fd 00 01 00 00 75 c8 90 00 } //1
		$a_03_1 = {6a 40 68 00 10 00 00 ff 35 78 ef 42 00 56 ff 15 08 e0 41 00 a3 90 01 03 00 8b fe 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}