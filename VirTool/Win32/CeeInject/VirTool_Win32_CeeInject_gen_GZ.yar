
rule VirTool_Win32_CeeInject_gen_GZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3e 8b 48 3c a1 [0-20] 36 03 04 24 [0-10] 3e 0f b7 40 06 83 f8 ?? 74 01 c3 } //1
		$a_03_1 = {0f b6 54 32 ff 33 d3 88 54 30 ff 4b 85 db 75 ?? 46 4f 75 ?? be ?? ?? ?? ?? b8 ?? ?? ?? ?? bb ?? ?? ?? ?? 30 18 4b 85 db 75 f9 40 4e 75 f0 8d 05 [0-10] ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}