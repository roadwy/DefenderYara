
rule VirTool_Win32_Injector_gen_AX{
	meta:
		description = "VirTool:Win32/Injector.gen!AX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 02 eb 34 ff b5 f8 fd ff ff 6a 00 ff 95 60 fe ff ff 89 45 e4 8b 85 b4 fd ff ff 03 45 e4 89 85 b4 fd ff ff 68 90 01 04 8d 85 e4 fe ff ff 50 ff 15 90 01 04 eb aa 90 00 } //01 00 
		$a_01_1 = {6a 04 68 00 30 00 00 8b 85 b4 fd ff ff 6b c0 03 50 6a 00 ff 15 } //01 00 
		$a_01_2 = {6b c9 28 03 4d 0c 8d 84 01 f8 00 00 00 89 85 f0 fc ff ff } //01 00 
	condition:
		any of ($a_*)
 
}