
rule VirTool_Win32_Injector_gen_FH{
	meta:
		description = "VirTool:Win32/Injector.gen!FH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 ec 5f fa e9 } //01 00 
		$a_01_1 = {68 2b ed 9b 51 } //01 00 
		$a_01_2 = {68 17 ee b4 cf } //01 00 
		$a_01_3 = {68 02 eb d4 97 } //01 00 
		$a_01_4 = {68 cb 6a a7 a0 } //01 00 
		$a_01_5 = {68 23 f9 35 9d } //06 00 
		$a_03_6 = {8b 48 74 ff d1 85 c0 75 09 8b 55 f8 83 c2 01 89 55 f8 8b 45 f0 50 e8 90 01 04 8b 08 ff d1 e9 90 00 } //04 00 
		$a_01_7 = {8b 48 74 ff d1 83 7d 18 00 74 0a 8b 55 18 8b 45 fc 89 02 eb 0d } //00 00 
		$a_00_8 = {5d 04 00 00 23 2d } //03 80 
	condition:
		any of ($a_*)
 
}