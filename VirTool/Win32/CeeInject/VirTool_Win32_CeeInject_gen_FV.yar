
rule VirTool_Win32_CeeInject_gen_FV{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FV,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 00 77 00 73 00 5c 00 25 00 77 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  %ws\%ws.exe
		$a_01_1 = {80 24 31 00 8d 5c 31 01 89 1a 47 83 c2 04 } //01 00 
		$a_01_2 = {53 ff 76 54 ff 75 08 ff 76 34 ff 75 e8 } //00 00 
	condition:
		any of ($a_*)
 
}