
rule VirTool_Win32_VBInject_gen_JX{
	meta:
		description = "VirTool:Win32/VBInject.gen!JX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 ?? 0f 80 ?? 00 00 00 89 45 08 8b 45 08 3b 45 ?? 7f ?? c7 45 ?? ?? 00 00 00 ff 75 ?? ff 75 08 e8 ?? ?? ?? ff 8b d0 } //1
		$a_80_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 76 62 61 6d 65 2e 64 6c 6c 00 } //C:\WINDOWS\SYSTEM32\vbame.dll  1
		$a_01_2 = {c7 00 40 08 75 02 c7 40 04 8b 00 c2 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}