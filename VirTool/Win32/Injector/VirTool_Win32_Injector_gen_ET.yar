
rule VirTool_Win32_Injector_gen_ET{
	meta:
		description = "VirTool:Win32/Injector.gen!ET,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 96 bc 08 00 00 3b d0 76 4c 0f b6 8c 06 c0 08 00 00 0f b6 bc 06 c8 08 00 00 } //01 00 
		$a_03_1 = {6a 02 6a 00 53 ff 15 90 01 04 53 8d be bc 08 00 00 ff 15 90 01 04 53 89 07 ff 15 90 01 04 8b 07 53 40 50 8d 86 c0 08 00 00 6a 01 50 90 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}