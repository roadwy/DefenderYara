
rule VirTool_Win32_Injector_gen_BG{
	meta:
		description = "VirTool:Win32/Injector.gen!BG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 ff ff ff 00 eb 05 50 ff 0c 24 58 0b c0 75 f7 } //01 00 
		$a_03_1 = {68 4c 06 e1 47 e8 90 01 04 68 6b 59 6f 06 50 e8 90 00 } //01 00 
		$a_03_2 = {77 8d 00 c6 85 90 01 04 51 8d 00 c6 85 90 01 04 75 8d 00 c6 85 90 01 04 65 8d 00 c6 85 90 01 04 72 8d 00 c6 85 90 01 04 79 8d 00 c6 85 90 01 04 53 8d 00 c6 85 90 01 04 79 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}