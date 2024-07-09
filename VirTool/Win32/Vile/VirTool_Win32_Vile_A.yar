
rule VirTool_Win32_Vile_A{
	meta:
		description = "VirTool:Win32/Vile.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 6f 2f 74 61 72 67 65 74 2f 65 78 65 } //1 to/target/exe
		$a_01_1 = {64 6c 6c 5f 69 6e 6a } //1 dll_inj
		$a_01_2 = {49 6e 6a 65 63 74 50 72 6f 63 } //1 InjectProc
		$a_03_3 = {41 b9 00 30 00 00 c7 44 24 20 04 00 00 00 48 8b c8 4c 8b c3 33 d2 48 8b f0 ff 15 ?? ?? ?? ?? 4c 8b cb 48 c7 44 24 20 00 00 00 00 48 8b d0 4c 8d 84 24 80 02 00 00 48 8b ce 48 8b e8 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}