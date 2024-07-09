
rule VirTool_Win32_Injector_gen_EH{
	meta:
		description = "VirTool:Win32/Injector.gen!EH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 00 07 00 01 00 } //1
		$a_03_1 = {8b 48 50 8b 50 34 a1 ?? ?? ?? ?? 6a 40 68 00 30 00 00 51 52 50 ff 54 24 } //1
		$a_03_2 = {33 db 66 3b 41 06 73 ?? 33 ed 8b 57 3c 03 d5 8b 8c 3a 08 01 00 00 8d 84 3a f8 00 00 00 8b 50 14 8b 40 0c } //1
		$a_03_3 = {8b 42 28 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 81 b0 00 00 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}