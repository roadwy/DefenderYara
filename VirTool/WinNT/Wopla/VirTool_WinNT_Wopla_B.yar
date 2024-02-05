
rule VirTool_WinNT_Wopla_B{
	meta:
		description = "VirTool:WinNT/Wopla.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {3b c6 89 45 10 7d b0 e9 80 00 00 00 b8 06 00 00 80 e9 81 00 00 00 53 8b 45 14 8b 4d 1c 8d 1c 08 8d 45 28 } //01 00 
		$a_02_1 = {ff 34 88 e8 90 01 02 ff ff 8b 4d 10 89 01 8b 45 08 0f 22 c0 fb b0 01 eb 02 32 c0 5d c2 0c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}