
rule VirTool_Win32_Vanti_gen_B{
	meta:
		description = "VirTool:Win32/Vanti.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ec bb 00 90 02 28 81 c3 00 00 01 00 90 02 50 83 f9 00 74 90 02 40 66 81 90 04 01 03 38 2d 3b 4d 5a 90 02 50 83 f8 00 90 02 40 81 3a 4b 45 52 4e 90 02 30 5d c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}