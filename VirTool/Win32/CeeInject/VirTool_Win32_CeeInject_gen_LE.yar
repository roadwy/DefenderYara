
rule VirTool_Win32_CeeInject_gen_LE{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {18 03 07 03 04 18 5c 41 48 11 01 0d 00 } //1
		$a_01_1 = {73 66 75 6d 61 74 6f 00 } //1 晳浵瑡o
		$a_01_2 = {b8 07 00 00 00 c7 84 24 90 04 00 00 31 00 00 00 8b 8c 24 94 04 00 00 0f be 8c 0c a2 04 00 00 8b 94 24 94 04 00 00 89 84 24 d0 00 00 00 89 d0 99 8b b4 24 d0 00 00 00 f7 fe 0f be 84 14 9a 04 00 00 31 c1 88 cb 8b 84 24 94 04 00 00 88 9c 04 a2 04 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}