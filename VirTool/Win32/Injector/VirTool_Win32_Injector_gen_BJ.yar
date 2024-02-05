
rule VirTool_Win32_Injector_gen_BJ{
	meta:
		description = "VirTool:Win32/Injector.gen!BJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 74 24 6c 57 66 81 3e 4d 5a 0f 90 01 05 8b 4e 3c 8b de 03 d9 81 3b 50 45 00 00 0f 90 01 05 b9 11 00 00 00 90 00 } //01 00 
		$a_01_1 = {33 db 8a 1c 0f 8b ea 81 e5 ff 00 00 00 03 c3 03 c5 25 ff 00 00 80 } //01 00 
		$a_01_2 = {8a 1c 06 88 54 24 18 88 1c 01 8b 5c 24 18 88 14 06 33 d2 8a 14 01 } //00 00 
	condition:
		any of ($a_*)
 
}