
rule VirTool_Win32_Obfuscator_gen_D{
	meta:
		description = "VirTool:Win32/Obfuscator.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {83 e0 fc 33 c1 83 c0 ?? 83 c0 ?? 83 c0 [0-04] a3 ?? ?? ?? 00 c1 c8 18 89 02 83 c2 04 c7 02 02 00 00 00 } //1
		$a_00_1 = {51 75 65 75 65 55 73 65 72 41 50 43 } //1 QueueUserAPC
		$a_02_2 = {8a 26 32 e0 88 26 46 c7 05 ?? ?? ?? 00 00 00 00 00 e2 d2 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}