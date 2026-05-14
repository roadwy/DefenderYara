
rule VirTool_Win32_Geinjesz_A{
	meta:
		description = "VirTool:Win32/Geinjesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 02 03 c6 3b c8 ?? ?? 8b 02 85 c0 ?? ?? 33 f6 85 c0 ?? ?? 8a 43 10 ?? ?? ?? 03 4a fc 46 30 01 3b 32 } //1
		$a_03_1 = {0f b7 44 56 08 8b c8 81 e1 00 f0 00 00 81 f9 00 a0 00 00 ?? ?? 8b 4d fc 25 ff 0f 00 00 03 06 01 0c 18 42 3b d7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}