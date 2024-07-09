
rule VirTool_Win32_Vanti_gen_B{
	meta:
		description = "VirTool:Win32/Vanti.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ec bb 00 [0-28] 81 c3 00 00 01 00 [0-50] 83 f9 00 74 [0-40] 66 81 [38-3b] 4d 5a [0-50] 83 f8 00 [0-40] 81 3a 4b 45 52 4e [0-30] 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}