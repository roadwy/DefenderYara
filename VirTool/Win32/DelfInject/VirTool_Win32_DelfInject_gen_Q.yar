
rule VirTool_Win32_DelfInject_gen_Q{
	meta:
		description = "VirTool:Win32/DelfInject.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 } //1 RtlDecompressBuffer
		$a_01_1 = {4d 44 41 54 41 31 00 00 4d 44 41 54 41 32 } //1
		$a_02_2 = {8b 45 fc 8a 44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 4a e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 dc } //1
		$a_03_3 = {44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 80 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 da 90 09 04 00 8b 45 fc (8a|8b) } //1
		$a_03_4 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b (85 ?? ?? ff ff 45|?? 50 90 03) 01 01 ff e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}