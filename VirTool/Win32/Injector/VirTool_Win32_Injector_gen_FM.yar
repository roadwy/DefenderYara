
rule VirTool_Win32_Injector_gen_FM{
	meta:
		description = "VirTool:Win32/Injector.gen!FM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ac 51 8b 0f 33 c1 aa 59 4b 75 04 5b 2b f3 53 49 75 ee } //01 00 
		$a_01_1 = {8b f1 33 c0 66 ad 85 c0 74 05 03 c1 50 eb f3 89 45 0c 89 45 10 6a 01 59 ff 55 e8 } //01 00 
		$a_01_2 = {e8 22 00 00 00 b0 0d 49 00 ea 00 0a 01 24 01 88 01 07 02 fa 02 3f 03 fb 05 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}