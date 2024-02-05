
rule VirTool_Win32_Injector_AD{
	meta:
		description = "VirTool:Win32/Injector.AD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4a 88 10 40 8a 10 84 d2 75 f6 b8 90 01 04 eb 04 90 00 } //01 00 
		$a_03_1 = {8a 1c 03 30 19 40 3b 44 24 90 02 10 42 3b 54 24 90 01 01 72 90 14 8b 4c 24 90 01 01 01 d1 8b 5c 24 90 00 } //01 00 
		$a_01_2 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}