
rule VirTool_Win32_CeeInject_gen_CZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 7e 34 57 83 c2 08 52 90 01 01 ff 15 90 01 04 8b 4e 28 03 0f 90 00 } //01 00 
		$a_01_1 = {0f b7 48 06 43 83 c6 28 3b d9 7c d8 eb 04 } //01 00 
	condition:
		any of ($a_*)
 
}