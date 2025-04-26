
rule VirTool_Win32_DelfInject_gen_BR{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 68 00 04 00 00 53 e8 ?? ?? ff ff 6a 00 8d 45 f8 50 6a 01 8d 45 f7 50 53 e8 ?? ?? ff ff 6a 00 6a 00 68 01 04 00 00 53 e8 ?? ?? ff ff 6a 00 8d 45 f8 50 6a 04 } //2
		$a_01_1 = {d3 e0 8b c8 8b 45 f0 33 d2 f7 f1 89 55 f0 b9 00 01 00 00 8b c3 99 f7 f9 } //1
		$a_03_2 = {8b de 66 81 3b 4d 5a 0f 85 ?? ?? 00 00 [0-20] 8b c6 33 d2 52 50 8b 43 3c 99 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}