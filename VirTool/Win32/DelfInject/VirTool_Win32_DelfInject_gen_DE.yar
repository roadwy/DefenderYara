
rule VirTool_Win32_DelfInject_gen_DE{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {5a 92 8b ca 99 f7 f9 8b d8 85 db 7c 0f 43 8d 45 f4 8b 55 f8 e8 ?? ?? ?? ?? 4b 75 f2 8b 45 fc e8 ?? ?? ?? ?? 8b d8 85 db 7e 36 be 01 00 00 00 90 90 90 90 90 90 90 90 90 90 8b 45 fc 8a 44 30 ff 8b 55 f4 8a 54 32 ff 32 c2 88 45 f3 8d 45 ec 8a 55 f3 e8 ?? ?? ?? ?? 8b 55 ec 8b c7 e8 ?? ?? ?? ?? 46 4b 75 cf } //1
		$a_01_1 = {c1 e3 02 03 f3 8b 1e 03 d8 8b f3 8b 5d ec 8b 5b 1c 03 d8 c1 e2 02 03 da } //1
		$a_01_2 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 1c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}