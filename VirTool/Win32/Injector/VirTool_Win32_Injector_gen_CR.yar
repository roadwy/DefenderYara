
rule VirTool_Win32_Injector_gen_CR{
	meta:
		description = "VirTool:Win32/Injector.gen!CR,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {45 6e 75 6d 65 72 61 74 65 64 20 57 69 6e 64 6f 77 20 45 78 70 6c 6f 72 65 72 00 } //01 00 
		$a_03_1 = {b8 ff ff ff 0f eb 90 14 eb 90 14 eb 90 00 } //01 00 
		$a_03_2 = {68 00 80 00 00 eb 90 14 eb 90 14 eb 90 00 } //01 00 
		$a_03_3 = {8d 45 fc eb 90 14 eb 90 14 e9 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}