
rule VirTool_Win32_Injector_gen_EX{
	meta:
		description = "VirTool:Win32/Injector.gen!EX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 56 57 89 8d 90 01 02 ff ff c6 85 90 01 02 ff ff 6d c6 85 90 01 02 ff ff 79 c6 85 90 01 02 ff ff 61 c6 85 90 01 02 ff ff 70 c6 85 90 01 02 ff ff 70 c6 85 90 01 02 ff ff 2e c6 85 90 01 02 ff ff 65 c6 85 90 01 02 ff ff 78 c6 85 90 01 02 ff ff 65 c6 85 90 01 02 ff ff 00 68 90 01 04 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 83 c4 08 89 45 90 01 01 83 7d 90 01 01 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}