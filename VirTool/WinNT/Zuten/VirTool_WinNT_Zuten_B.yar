
rule VirTool_WinNT_Zuten_B{
	meta:
		description = "VirTool:WinNT/Zuten.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c3 0b c6 06 e9 89 5e 01 8b 4d 2c ff 15 } //01 00 
		$a_01_1 = {c6 45 e6 8d c6 45 e7 45 c6 45 e8 08 c6 45 e9 50 c6 45 ea 6a c6 45 eb 09 c6 45 ec 6a c6 45 ed fe c6 45 ef 15 } //01 00 
		$a_01_2 = {c6 45 ea 8d c6 45 eb 45 c6 45 ec 08 } //00 00 
	condition:
		any of ($a_*)
 
}