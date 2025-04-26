
rule VirTool_Win32_CeeInject_gen_CY{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 d4 56 69 72 74 c7 45 d8 75 61 6c 50 c7 45 dc 72 6f 74 65 c7 45 e0 63 74 45 78 c6 45 e4 00 c6 45 e5 4b } //1
		$a_01_1 = {25 00 f0 ff ff 3b c8 72 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}