
rule VirTool_Win32_VBInject_gen_JN{
	meta:
		description = "VirTool:Win32/VBInject.gen!JN,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {75 ff d8 ff e0 20 10 4a 46 49 46 } //1
		$a_03_1 = {b9 58 00 00 00 ff d6 8d 55 d4 88 45 d4 52 e8 ?? ?? ?? ?? b9 59 00 00 00 ff d6 88 45 d4 8d 45 d4 50 e8 ?? ?? ?? ?? b9 59 00 00 00 ff d6 } //1
		$a_03_2 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}