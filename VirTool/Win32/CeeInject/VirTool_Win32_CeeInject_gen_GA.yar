
rule VirTool_Win32_CeeInject_gen_GA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 ff 15 90 01 04 50 8b 55 08 52 ff 15 90 00 } //01 00 
		$a_02_1 = {6a 00 8b 95 90 01 02 ff ff 8b 42 90 01 01 50 8b 4d 90 01 01 51 8b 95 90 01 02 ff ff 8b 42 90 01 01 50 8b 8d 90 01 02 ff ff 51 ff 15 90 01 04 c7 85 90 01 02 ff ff 00 00 00 00 eb 90 00 } //01 00 
		$a_02_2 = {6a 00 6a 04 8b 8d 90 01 02 ff ff 83 c1 34 51 8b 95 90 01 02 ff ff 83 c2 08 52 8b 85 90 01 02 ff ff 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}