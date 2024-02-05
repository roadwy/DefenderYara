
rule VirTool_Win32_Injector_HD{
	meta:
		description = "VirTool:Win32/Injector.HD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 48 74 12 47 47 8b 45 f8 ff 45 f8 47 8b 4d f4 47 40 3b c1 72 c5 } //01 00 
		$a_01_1 = {0f b7 00 8b 4e 1a 4e 4e 4e 8d 04 81 4e 8b 4d fc 03 c1 8b 00 03 c1 eb } //01 00 
		$a_01_2 = {03 c1 03 c2 4e 4e 4e 0f b7 00 8b 4e 1e 8d 04 81 4e 8b 4d fc 03 c1 8b 00 03 c1 eb c8 } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}