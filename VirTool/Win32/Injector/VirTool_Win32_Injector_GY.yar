
rule VirTool_Win32_Injector_GY{
	meta:
		description = "VirTool:Win32/Injector.GY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 8d 8d 34 ff ff ff 51 53 68 1f 00 0f 00 8d 90 01 03 ff ff 51 ff 55 cc 85 c0 90 00 } //01 00 
		$a_01_1 = {5b 53 51 8b 0f ac 33 c1 aa 59 4b 75 04 5b 2b f3 53 e2 ef } //01 00 
		$a_01_2 = {8b 55 14 8b 4a 04 ff 55 e8 55 59 ff d0 50 8b 45 10 ff 4d 10 ba 1c 00 00 00 } //01 00 
		$a_01_3 = {3b fa 72 04 41 5a eb f3 5e 8b 55 14 89 4a 0c 67 e3 03 ff 55 e8 } //02 00 
		$a_01_4 = {74 05 03 c2 50 eb f3 89 45 0c 89 45 10 b9 01 00 00 00 ff 55 e8 } //01 00 
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}