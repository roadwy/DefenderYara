
rule VirTool_Win32_DelfInject_gen_AT{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 84 70 02 00 00 55 68 86 45 40 00 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 8b cb 66 81 39 4d 5a 74 0a } //1
		$a_01_1 = {b8 10 69 40 00 e8 90 d5 ff ff 33 c0 a3 d0 a6 40 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}