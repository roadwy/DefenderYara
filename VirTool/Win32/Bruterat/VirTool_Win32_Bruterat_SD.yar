
rule VirTool_Win32_Bruterat_SD{
	meta:
		description = "VirTool:Win32/Bruterat.SD,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 41 5f 55 50 53 51 52 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 48 89 e5 48 83 e4 f0 } //01 00 
		$a_01_1 = {41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 41 59 41 58 5f 5e 5a 59 5b 58 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}