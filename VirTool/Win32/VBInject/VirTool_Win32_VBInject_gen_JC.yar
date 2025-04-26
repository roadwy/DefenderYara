
rule VirTool_Win32_VBInject_gen_JC{
	meta:
		description = "VirTool:Win32/VBInject.gen!JC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 e6 ff 00 00 00 66 89 34 01 8b 45 e0 83 c0 01 0f 80 ?? ?? 00 00 99 f7 7d d8 b8 01 00 00 00 03 c7 } //1
		$a_03_1 = {c7 04 c1 eb e7 8b c5 8b 55 cc 8d 8d ?? ?? ff ff c7 44 c2 04 5f 5e 5b 59 } //1
		$a_03_2 = {c7 45 88 08 80 00 00 ff 15 ?? ?? ?? ?? 8d 4d d0 66 8b f0 ff 15 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 8d 45 ac 8d 4d bc 50 51 6a 02 ff d3 83 c4 0c 66 85 f6 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}