
rule VirTool_Win32_Injector_IC{
	meta:
		description = "VirTool:Win32/Injector.IC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 08 2b 4d fc 8b 55 08 03 55 f8 88 0a } //01 00 
		$a_01_1 = {6b c9 28 03 4d 0c 8d 94 01 f8 00 00 00 } //01 00 
		$a_01_2 = {81 e1 ff ff 00 00 81 f9 d0 07 00 00 7d 04 b0 01 eb 42 } //00 00 
	condition:
		any of ($a_*)
 
}